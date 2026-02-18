//! Migration path and backward compatibility layer.
//!
//! Allows gradual adoption of RaptorQ symbol-native operations while
//! maintaining compatibility with existing traditional code paths.
//! Features can be enabled individually via [`MigrationBuilder`].

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::EncodingConfig;
use crate::types::symbol::ObjectId;

// ============================================================================
// MigrationMode
// ============================================================================

/// Controls how operations handle dual-mode values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MigrationMode {
    /// Only use traditional mode (no RaptorQ).
    TraditionalOnly,
    /// Default to traditional, RaptorQ opt-in.
    #[default]
    PreferTraditional,
    /// Use RaptorQ when beneficial, fall back to traditional.
    Adaptive,
    /// Default to RaptorQ, traditional opt-in.
    PreferSymbolNative,
    /// Only use RaptorQ (errors on traditional-only operations).
    SymbolNativeOnly,
}

impl MigrationMode {
    /// Whether to use RaptorQ for a given operation.
    ///
    /// Explicit hints always override the mode. In `Adaptive` mode,
    /// payloads larger than 1024 bytes default to RaptorQ.
    #[must_use]
    pub fn should_use_raptorq(&self, hint: Option<bool>, data_size: usize) -> bool {
        match (self, hint) {
            // Explicit hints always win; otherwise prefer symbol-native modes.
            (_, Some(true)) | (Self::SymbolNativeOnly | Self::PreferSymbolNative, None) => true,
            (_, Some(false)) | (Self::TraditionalOnly | Self::PreferTraditional, None) => false,
            // Adaptive mode uses size heuristic
            (Self::Adaptive, None) => data_size > 1024,
        }
    }
}

// ============================================================================
// MigrationFeature
// ============================================================================

/// Individual features that can be toggled during migration.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum MigrationFeature {
    /// Enable RaptorQ for join operations.
    JoinEncoding,
    /// Enable RaptorQ for race operations.
    RaceEncoding,
    /// Enable distributed region encoding.
    DistributedRegions,
    /// Enable symbol-based cancellation.
    SymbolCancellation,
    /// Enable symbol-based tracing.
    SymbolTracing,
    /// Enable epoch barriers.
    EpochBarriers,
}

impl MigrationFeature {
    /// Returns an iterator over all features.
    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::JoinEncoding,
            Self::RaceEncoding,
            Self::DistributedRegions,
            Self::SymbolCancellation,
            Self::SymbolTracing,
            Self::EpochBarriers,
        ]
        .into_iter()
    }
}

// ============================================================================
// MigrationConfig
// ============================================================================

/// Active migration configuration.
#[derive(Debug, Clone, Default)]
pub struct MigrationConfig {
    /// Enabled features.
    features: HashSet<MigrationFeature>,
    /// Global migration mode.
    mode: MigrationMode,
    /// Per-operation overrides.
    overrides: HashMap<String, MigrationMode>,
}

impl MigrationConfig {
    /// Returns true if a feature is enabled.
    #[must_use]
    pub fn is_enabled(&self, feature: MigrationFeature) -> bool {
        self.features.contains(&feature)
    }

    /// Returns the global migration mode.
    #[must_use]
    pub fn mode(&self) -> MigrationMode {
        self.mode
    }

    /// Returns the set of enabled features.
    #[must_use]
    pub fn enabled_features(&self) -> &HashSet<MigrationFeature> {
        &self.features
    }

    /// Returns the mode override for a specific operation, if set.
    #[must_use]
    pub fn mode_for(&self, operation: &str) -> MigrationMode {
        self.overrides.get(operation).copied().unwrap_or(self.mode)
    }
}

// ============================================================================
// MigrationBuilder
// ============================================================================

/// Builder for [`MigrationConfig`].
#[derive(Debug, Default)]
pub struct MigrationBuilder {
    /// Features to enable.
    features: HashSet<MigrationFeature>,
    /// Global mode.
    mode: MigrationMode,
    /// Per-operation overrides.
    overrides: HashMap<String, MigrationMode>,
}

impl MigrationBuilder {
    /// Creates a new builder with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable a specific migration feature.
    #[must_use]
    pub fn enable(mut self, feature: MigrationFeature) -> Self {
        self.features.insert(feature);
        self
    }

    /// Disable a specific feature.
    #[must_use]
    pub fn disable(mut self, feature: MigrationFeature) -> Self {
        self.features.remove(&feature);
        self
    }

    /// Set the global migration mode.
    #[must_use]
    pub fn with_mode(mut self, mode: MigrationMode) -> Self {
        self.mode = mode;
        self
    }

    /// Override the mode for a specific operation.
    #[must_use]
    pub fn override_operation(mut self, operation: impl Into<String>, mode: MigrationMode) -> Self {
        self.overrides.insert(operation.into(), mode);
        self
    }

    /// Enable all features (full RaptorQ mode).
    #[must_use]
    pub fn full_raptorq(mut self) -> Self {
        self.features = MigrationFeature::all().collect();
        self.mode = MigrationMode::SymbolNativeOnly;
        self
    }

    /// Build the migration configuration.
    #[must_use]
    pub fn build(self) -> MigrationConfig {
        MigrationConfig {
            features: self.features,
            mode: self.mode,
            overrides: self.overrides,
        }
    }
}

/// Entry point for configuring migration.
#[must_use]
pub fn configure_migration() -> MigrationBuilder {
    MigrationBuilder::new()
}

// ============================================================================
// DualValueError
// ============================================================================

/// Errors from [`DualValue`] operations.
#[derive(Debug)]
pub enum DualValueError {
    /// Serialization to symbol encoding failed.
    SerializationFailed(String),
    /// Deserialization from symbol encoding failed.
    DeserializationFailed(String),
}

impl std::fmt::Display for DualValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationFailed(msg) => write!(f, "serialization failed: {msg}"),
            Self::DeserializationFailed(msg) => write!(f, "deserialization failed: {msg}"),
        }
    }
}

impl std::error::Error for DualValueError {}

// ============================================================================
// DualValue
// ============================================================================

/// A value that can be held in either traditional or symbol-encoded form.
///
/// In traditional mode, the value is stored directly. In symbol-encoded mode,
/// the value is serialized and can be transmitted as symbols. Both forms
/// support retrieving the underlying value via [`get`][DualValue::get].
pub enum DualValue<T> {
    /// Traditional direct value.
    Traditional(T),
    /// Symbol-encoded value with serialized bytes and metadata.
    SymbolNative {
        /// Serialized representation.
        serialized: Vec<u8>,
        /// Object identifier.
        object_id: ObjectId,
        /// Type marker.
        _phantom: PhantomData<T>,
    },
}

impl<T> DualValue<T> {
    /// Returns true if this value is in symbol-encoded form.
    #[must_use]
    pub fn uses_raptorq(&self) -> bool {
        matches!(self, Self::SymbolNative { .. })
    }

    /// Returns true if this value is in traditional form.
    #[must_use]
    pub fn is_traditional(&self) -> bool {
        matches!(self, Self::Traditional(_))
    }
}

impl<T: Clone + Serialize + DeserializeOwned> DualValue<T> {
    /// Retrieves the underlying value, deserializing if necessary.
    pub fn get(&self) -> Result<T, DualValueError> {
        match self {
            Self::Traditional(v) => Ok(v.clone()),
            Self::SymbolNative { serialized, .. } => serde_json::from_slice(serialized)
                .map_err(|e| DualValueError::DeserializationFailed(e.to_string())),
        }
    }

    /// Converts to symbol-encoded form if not already.
    ///
    /// The `_config` parameter is reserved for future use with actual
    /// RaptorQ encoding configuration.
    pub fn ensure_symbols(&mut self, _config: &EncodingConfig) {
        if let Self::Traditional(v) = self {
            let serialized =
                serde_json::to_vec(v).expect("serialization of existing value should succeed");
            let object_id = ObjectId::new_for_test(0);
            *self = Self::SymbolNative {
                serialized,
                object_id,
                _phantom: PhantomData,
            };
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for DualValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Traditional(v) => f.debug_tuple("Traditional").field(v).finish(),
            Self::SymbolNative {
                serialized,
                object_id,
                ..
            } => f
                .debug_struct("SymbolNative")
                .field("bytes", &serialized.len())
                .field("object_id", object_id)
                .finish(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dual_value_traditional() {
        let value = DualValue::Traditional(42i32);
        assert_eq!(value.get().unwrap(), 42);
        assert!(!value.uses_raptorq());
    }

    #[test]
    fn test_dual_value_conversion() {
        let mut value = DualValue::Traditional("hello".to_string());
        let config = EncodingConfig::default();

        // Convert to symbol-native
        value.ensure_symbols(&config);
        assert!(matches!(value, DualValue::SymbolNative { .. }));

        // Still get same value
        assert_eq!(value.get().unwrap(), "hello".to_string());
    }

    #[test]
    fn test_migration_mode_decisions() {
        // Traditional only never uses RaptorQ
        assert!(!MigrationMode::TraditionalOnly.should_use_raptorq(None, 10000));

        // Symbol-native only always uses RaptorQ
        assert!(MigrationMode::SymbolNativeOnly.should_use_raptorq(None, 10));

        // Hints override mode
        assert!(MigrationMode::TraditionalOnly.should_use_raptorq(Some(true), 10));
        assert!(!MigrationMode::SymbolNativeOnly.should_use_raptorq(Some(false), 10));

        // Adaptive uses heuristics
        assert!(!MigrationMode::Adaptive.should_use_raptorq(None, 100));
        assert!(MigrationMode::Adaptive.should_use_raptorq(None, 10000));
    }

    #[test]
    fn test_migration_builder() {
        let config = configure_migration()
            .enable(MigrationFeature::JoinEncoding)
            .enable(MigrationFeature::RaceEncoding)
            .build();

        assert!(config.is_enabled(MigrationFeature::JoinEncoding));
        assert!(config.is_enabled(MigrationFeature::RaceEncoding));
        assert!(!config.is_enabled(MigrationFeature::DistributedRegions));
    }

    #[test]
    fn test_full_raptorq_mode() {
        let config = configure_migration().full_raptorq().build();

        for feature in MigrationFeature::all() {
            assert!(config.is_enabled(feature));
        }
    }

    #[test]
    fn test_migration_mode_default() {
        let mode = MigrationMode::default();
        assert_eq!(mode, MigrationMode::PreferTraditional);
    }

    #[test]
    fn test_migration_builder_disable() {
        let config = configure_migration()
            .full_raptorq()
            .disable(MigrationFeature::SymbolTracing)
            .build();

        assert!(config.is_enabled(MigrationFeature::JoinEncoding));
        assert!(!config.is_enabled(MigrationFeature::SymbolTracing));
    }

    #[test]
    fn test_per_operation_override() {
        let config = configure_migration()
            .with_mode(MigrationMode::PreferTraditional)
            .override_operation("heavy_join", MigrationMode::PreferSymbolNative)
            .build();

        assert_eq!(config.mode(), MigrationMode::PreferTraditional);
        assert_eq!(
            config.mode_for("heavy_join"),
            MigrationMode::PreferSymbolNative
        );
        assert_eq!(
            config.mode_for("other_op"),
            MigrationMode::PreferTraditional
        );
    }
}
