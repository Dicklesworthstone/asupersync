//! Strictly safe, resource-bounded Thompson-IR execution.
//!
//! This private R3.4 surface executes only programs that pass the R3.3
//! validator. The R3.4.1 entry point implements whole-haystack language
//! recognition. The R3.4.2 entry points add one-shot leftmost-first selection,
//! ordered greedy/lazy execution, and bounded capture histories. R3.4.3 adds
//! deterministic match/capture iteration, explicit overlap policy, Unicode-safe
//! zero-width progress, and ordered replacement spans. R3.4.4 adds explicit
//! caller-supplied cancellation checkpoints and terminal adversarial evidence.
//! R3.5.3 adds a private, bounded replacement-template parser and capture
//! expander, including a separately named strict diagnostic mode. Production
//! privacy wiring and dependency replacement remain downstream work.

use core::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use parking_lot::Mutex;

use super::regex_boundaries::BoundaryEvalErrorKind;
use super::regex_ir::{
    CaptureSlot, ClassId, CompileError, CompileErrorKind, CompileLimits, Instruction, Program,
    StateId,
};
use super::regex_lowering::{
    PrivateCompileError, PrivateCompileLimits, compile_private_with_captures,
};
use super::regex_semantics::{ByteRange, CanonicalRanges, ScalarRange};

pub const VM_ID: &str = "ASUP-REGEX-THREAD-SET-VM-V1";
pub const VM_SCHEMA_VERSION: u16 = 1;
pub const CAPTURE_VM_ID: &str = "ASUP-REGEX-PRIORITY-CAPTURE-VM-V1";
pub const CAPTURE_VM_SCHEMA_VERSION: u16 = 1;
pub const ITERATION_VM_ID: &str = "ASUP-REGEX-ITERATION-VM-V1";
pub const ITERATION_VM_SCHEMA_VERSION: u16 = 1;

pub const DEFAULT_MAX_INPUT_BYTES: usize = 1_048_576;
pub const DEFAULT_MAX_THREADS_PER_OFFSET: usize = 262_144;
pub const DEFAULT_MAX_VM_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_VM_WORK_UNITS: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_TRACE_EVENTS: usize = 256;

pub const MAX_UTF8_SCALAR_BYTES: usize = 4;
pub const OFFSET_BUCKET_COUNT: usize = MAX_UTF8_SCALAR_BYTES + 1;
pub const ACCOUNTED_VM_BASE_BYTES: u64 = 1_024;
pub const ACCOUNTED_THREAD_BYTES: u64 = 8;
pub const ACCOUNTED_SEEN_BYTE: u64 = 1;
pub const ACCOUNTED_TRACE_EVENT_BYTES: u64 = 32;

pub const DEFAULT_MAX_CAPTURE_HISTORY_NODES: usize = 262_144;
pub const CAPTURE_SEEN_KEYS_PER_STATE: usize = MAX_UTF8_SCALAR_BYTES;
pub const CAPTURE_OFFSET_BUCKET_COUNT: usize = 2;
pub const ACCOUNTED_CAPTURE_THREAD_BYTES: u64 = 64;
pub const ACCOUNTED_CAPTURE_TOUCHED_KEY_BYTES: u64 = 8;
pub const ACCOUNTED_CAPTURE_HISTORY_NODE_BYTES: u64 = 64;
pub const ACCOUNTED_CAPTURE_HISTORY_ALLOCATION_FLOOR_BYTES: u64 = 256;
pub const ACCOUNTED_CAPTURE_RESULT_SLOT_BYTES: u64 = 32;
pub const DEFAULT_MAX_ITERATED_MATCHES: usize = 262_144;
pub const DEFAULT_MAX_ITERATION_TRACE_EVENTS: usize = 256;
pub const ACCOUNTED_ITERATION_MATCH_BYTES: u64 = 128;
pub const ACCOUNTED_ITERATION_TRACE_EVENT_BYTES: u64 = 80;
pub const DEFAULT_CANCELLATION_CHECK_INTERVAL_WORK_UNITS: u64 = 1_024;
pub const DEFAULT_MAX_REPLACEMENT_TEMPLATE_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_REPLACEMENT_TOKENS: usize = 16 * 1024;
pub const DEFAULT_MAX_REPLACEMENT_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_REPLACEMENT_WORK_UNITS: u64 = 64 * 1024 * 1024;
// JSON can encode one input byte as a six-byte `\u00XX` escape. This ceiling
// therefore admits every pattern allowed by the default 1 MiB lexer budget,
// plus ample room for the explicit numeric limit fields.
pub const DEFAULT_MAX_PRIVATE_PATTERN_CONFIG_BYTES: usize = 8 * 1024 * 1024;
pub const PRIVATE_PATTERN_CONFIG_SCHEMA_VERSION: u16 = 1;
pub const DEFAULT_PRIVATE_PATTERN_CACHE_MAX_ENTRIES: usize = 256;
pub const DEFAULT_PRIVATE_PATTERN_CACHE_MAX_PATTERN_BYTES: usize = 1024 * 1024;
pub const DEFAULT_PRIVATE_PATTERN_CACHE_MAX_LIVE_ACCOUNTED_BYTES: u64 = 64 * 1024 * 1024;
// Default stage ceilings conservatively reserve about 1.135 GiB per compile.
// Keep the default count aligned with the 2 GiB aggregate ceiling; callers
// that lower the stage ceilings can explicitly admit more concurrent misses.
pub const DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILES: usize = 1;
pub const DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILE_ACCOUNTED_BYTES: u64 =
    2 * 1024 * 1024 * 1024;
pub const DEFAULT_PRIVATE_PATTERN_CACHE_MAX_LOOKUP_WORK_UNITS: u64 = 8 * 1024 * 1024;

// Conservative logical charge for the resident allocation, its Arc header,
// cache key fields, and cache-entry metadata. Program, capture-name, and
// retained-pattern bytes are added separately. This is deterministic policy
// accounting, not allocator-usable-size or RSS evidence.
pub const ACCOUNTED_PRIVATE_PATTERN_RESIDENT_OVERHEAD_BYTES: u64 = 512;
pub const ACCOUNTED_PRIVATE_PATTERN_COMPILE_BASE_BYTES: u64 = 4 * 1024;
pub const ACCOUNTED_PRIVATE_PATTERN_SOURCE_BYTE: u64 = 4;
pub const ACCOUNTED_PRIVATE_PATTERN_TOKEN_BYTES: u64 = 256;
pub const ACCOUNTED_PRIVATE_PATTERN_AST_NODE_BYTES: u64 = 256;
pub const ACCOUNTED_PRIVATE_PATTERN_SEMANTIC_ATOM_BYTES: u64 = 256;
pub const ACCOUNTED_PRIVATE_PATTERN_RANGE_BYTES: u64 = 32;
pub const ACCOUNTED_PRIVATE_PATTERN_FOLD_ATOM_BYTES: u64 = 256;
pub const ACCOUNTED_PRIVATE_PATTERN_BOUNDARY_BYTES: u64 = 64;
pub const ACCOUNTED_PRIVATE_PATTERN_LOOKUP_ENTRY_WORK_UNITS: u64 = 32;

const FINGERPRINT_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FINGERPRINT_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmLimits {
    pub max_input_bytes: usize,
    pub max_threads_per_offset: usize,
    pub max_memory_bytes: u64,
    pub max_work_units: u64,
    pub max_trace_events: usize,
}

impl Default for VmLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_threads_per_offset: DEFAULT_MAX_THREADS_PER_OFFSET,
            max_memory_bytes: DEFAULT_MAX_VM_MEMORY_BYTES,
            max_work_units: DEFAULT_MAX_VM_WORK_UNITS,
            max_trace_events: DEFAULT_MAX_TRACE_EVENTS,
        }
    }
}

impl VmLimits {
    const fn invariants_hold(self) -> bool {
        self.max_input_bytes > 0
            && self.max_threads_per_offset > 0
            && self.max_memory_bytes >= ACCOUNTED_VM_BASE_BYTES
            && self.max_work_units > 0
            && self.max_trace_events > 0
    }
}

/// Additional limits for prioritized capture execution.
///
/// Capture histories are persistent linked records. A `Save` appends one
/// bounded node and threads share the prior prefix instead of copying every
/// slot. `vm.max_memory_bytes` covers the complete capture executor, including
/// its thread frontiers, seen keys, retained trace, result slots, and history
/// nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureVmLimits {
    pub vm: VmLimits,
    pub max_capture_history_nodes: usize,
}

impl Default for CaptureVmLimits {
    fn default() -> Self {
        Self {
            vm: VmLimits::default(),
            max_capture_history_nodes: DEFAULT_MAX_CAPTURE_HISTORY_NODES,
        }
    }
}

impl CaptureVmLimits {
    const fn invariants_hold(self) -> bool {
        self.vm.invariants_hold() && self.max_capture_history_nodes > 0
    }
}

/// Aggregate limits for repeated search.
///
/// `capture.vm.max_work_units` and `capture.vm.max_memory_bytes` are whole
/// iteration ceilings, not fresh budgets for every search attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IterationVmLimits {
    pub capture: CaptureVmLimits,
    pub max_matches: usize,
    pub max_trace_events: usize,
}

impl Default for IterationVmLimits {
    fn default() -> Self {
        Self {
            capture: CaptureVmLimits::default(),
            max_matches: DEFAULT_MAX_ITERATED_MATCHES,
            max_trace_events: DEFAULT_MAX_ITERATION_TRACE_EVENTS,
        }
    }
}

impl IterationVmLimits {
    const fn invariants_hold(self) -> bool {
        self.capture.invariants_hold() && self.max_matches > 0 && self.max_trace_events > 0
    }
}

/// Aggregate ceilings for one private replacement-template operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementLimits {
    pub max_template_bytes: usize,
    pub max_tokens: usize,
    pub max_output_bytes: usize,
    pub max_work_units: u64,
}

impl Default for ReplacementLimits {
    fn default() -> Self {
        Self {
            max_template_bytes: DEFAULT_MAX_REPLACEMENT_TEMPLATE_BYTES,
            max_tokens: DEFAULT_MAX_REPLACEMENT_TOKENS,
            max_output_bytes: DEFAULT_MAX_REPLACEMENT_OUTPUT_BYTES,
            max_work_units: DEFAULT_MAX_REPLACEMENT_WORK_UNITS,
        }
    }
}

/// Versioned, explicit configuration for one private compiled pattern.
///
/// The pattern is retained only because this is the caller-owned
/// configuration document. Compilation results, errors, and `Debug` output do
/// not retain or render it. The recipe is crate-private and does not alter the
/// public [`crate::observability::otel::PrivacyConfig`] contract.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePatternConfig {
    pub schema_version: u16,
    pub pattern: String,
    pub compile_limits: PrivateCompileLimits,
    pub iteration_limits: IterationVmLimits,
    pub replacement_limits: ReplacementLimits,
}

impl PrivatePatternConfig {
    /// Construct a recipe with every current private limit made explicit.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            schema_version: PRIVATE_PATTERN_CONFIG_SCHEMA_VERSION,
            pattern: pattern.into(),
            compile_limits: PrivateCompileLimits::default(),
            iteration_limits: IterationVmLimits::default(),
            replacement_limits: ReplacementLimits::default(),
        }
    }

    /// Serialize the explicit configuration document deterministically.
    ///
    /// This is a structural serializer, not an admission step. Schema, limit,
    /// and pattern validation happens atomically in [`Self::load`] or
    /// [`Self::load_json`].
    pub fn to_json(&self) -> Result<String, PrivatePatternConfigError> {
        self.to_json_with_document_limit(DEFAULT_MAX_PRIVATE_PATTERN_CONFIG_BYTES)
    }

    /// Serialize without returning a document above the caller's ceiling.
    pub fn to_json_with_document_limit(
        &self,
        max_document_bytes: usize,
    ) -> Result<String, PrivatePatternConfigError> {
        let document = serde_json::to_string(self).map_err(PrivatePatternConfigError::encode)?;
        if document.len() > max_document_bytes {
            return Err(PrivatePatternConfigError::new(
                PrivatePatternConfigErrorKind::DocumentLimit,
            )
            .with_actual_limit(document.len(), max_document_bytes));
        }
        Ok(document)
    }

    /// Decode, validate, and compile a configuration as one atomic load.
    ///
    /// No configuration or partially compiled program escapes on error.
    pub fn load_json(document: &str) -> Result<LoadedPrivatePattern, PrivatePatternConfigError> {
        Self::load_json_with_document_limit(document, DEFAULT_MAX_PRIVATE_PATTERN_CONFIG_BYTES)
    }

    /// Decode and compile with an explicit pre-decode document ceiling.
    pub fn load_json_with_document_limit(
        document: &str,
        max_document_bytes: usize,
    ) -> Result<LoadedPrivatePattern, PrivatePatternConfigError> {
        if document.len() > max_document_bytes {
            return Err(PrivatePatternConfigError::new(
                PrivatePatternConfigErrorKind::DocumentLimit,
            )
            .with_actual_limit(document.len(), max_document_bytes));
        }
        let config = serde_json::from_str(document).map_err(PrivatePatternConfigError::decode)?;
        Self::load(config)
    }

    /// Validate and compile an already decoded configuration atomically.
    pub fn load(config: Self) -> Result<LoadedPrivatePattern, PrivatePatternConfigError> {
        if config.schema_version != PRIVATE_PATTERN_CONFIG_SCHEMA_VERSION {
            return Err(PrivatePatternConfigError::unsupported_schema(
                config.schema_version,
            ));
        }
        if let Some((field, actual, limit)) = invalid_iteration_limit(config.iteration_limits) {
            return Err(PrivatePatternConfigError::new(
                PrivatePatternConfigErrorKind::InvalidIterationLimits,
            )
            .with_field(field)
            .with_actual_limit(actual, limit));
        }
        let compiled = PrivateCompiledPattern::compile(&config.pattern, config.compile_limits)
            .map_err(PrivatePatternConfigError::compile)?;
        Ok(LoadedPrivatePattern {
            compiled,
            iteration_limits: config.iteration_limits,
            replacement_limits: config.replacement_limits,
        })
    }
}

impl fmt::Debug for PrivatePatternConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivatePatternConfig")
            .field("schema_version", &self.schema_version)
            .field("pattern_bytes", &self.pattern.len())
            .field("compile_limits", &self.compile_limits)
            .field("iteration_limits", &self.iteration_limits)
            .field("replacement_limits", &self.replacement_limits)
            .finish()
    }
}

/// Stable category for a private pattern-configuration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivatePatternConfigErrorKind {
    DocumentLimit,
    Decode,
    Encode,
    UnsupportedSchema,
    InvalidIterationLimits,
    Compile,
}

impl PrivatePatternConfigErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DocumentLimit => "RGX-CONFIG-E001",
            Self::Decode => "RGX-CONFIG-E002",
            Self::Encode => "RGX-CONFIG-E003",
            Self::UnsupportedSchema => "RGX-CONFIG-E004",
            Self::InvalidIterationLimits => "RGX-CONFIG-E005",
            Self::Compile => "RGX-CONFIG-E006",
        }
    }
}

/// Source-secret-safe private configuration diagnostic.
///
/// JSON text, pattern text, and user-provided string values are discarded.
/// Decode/encode failures retain only a normalized location; limit failures
/// retain a static field identifier and numeric bounds; compile failures retain
/// the already secret-safe private compiler diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivatePatternConfigError {
    pub kind: PrivatePatternConfigErrorKind,
    pub field: Option<&'static str>,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub schema_version: Option<u16>,
    pub actual: Option<u64>,
    pub limit: Option<u64>,
    pub compile_error: Option<PrivateCompileError>,
}

impl PrivatePatternConfigError {
    const fn new(kind: PrivatePatternConfigErrorKind) -> Self {
        Self {
            kind,
            field: None,
            line: None,
            column: None,
            schema_version: None,
            actual: None,
            limit: None,
            compile_error: None,
        }
    }

    fn decode(error: serde_json::Error) -> Self {
        Self {
            kind: PrivatePatternConfigErrorKind::Decode,
            field: None,
            line: Some(error.line()),
            column: Some(error.column()),
            schema_version: None,
            actual: None,
            limit: None,
            compile_error: None,
        }
    }

    fn encode(error: serde_json::Error) -> Self {
        Self {
            kind: PrivatePatternConfigErrorKind::Encode,
            field: None,
            line: Some(error.line()),
            column: Some(error.column()),
            schema_version: None,
            actual: None,
            limit: None,
            compile_error: None,
        }
    }

    const fn unsupported_schema(schema_version: u16) -> Self {
        Self {
            kind: PrivatePatternConfigErrorKind::UnsupportedSchema,
            field: None,
            line: None,
            column: None,
            schema_version: Some(schema_version),
            actual: None,
            limit: None,
            compile_error: None,
        }
    }

    const fn compile(compile_error: PrivateCompileError) -> Self {
        Self {
            kind: PrivatePatternConfigErrorKind::Compile,
            field: None,
            line: None,
            column: None,
            schema_version: None,
            actual: None,
            limit: None,
            compile_error: Some(compile_error),
        }
    }

    fn with_actual_limit<A, L>(mut self, actual: A, limit: L) -> Self
    where
        A: TryInto<u64>,
        L: TryInto<u64>,
    {
        self.actual = actual.try_into().ok();
        self.limit = limit.try_into().ok();
        self
    }

    const fn with_field(mut self, field: &'static str) -> Self {
        self.field = Some(field);
        self
    }

    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for PrivatePatternConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}] private regex configuration failed",
            self.kind.code()
        )?;
        if let Some(field) = self.field {
            write!(formatter, " field={field}")?;
        }
        if let (Some(line), Some(column)) = (self.line, self.column) {
            write!(formatter, " line={line} column={column}")?;
        }
        if let Some(schema_version) = self.schema_version {
            write!(formatter, " schema_version={schema_version}")?;
        }
        if let (Some(actual), Some(limit)) = (self.actual, self.limit) {
            write!(formatter, " actual={actual} limit={limit}")?;
        }
        if let Some(compile_error) = self.compile_error {
            write!(
                formatter,
                " compile_code={} compile_stage={}",
                compile_error.code(),
                compile_error.stage().code()
            )?;
        }
        Ok(())
    }
}

fn invalid_iteration_limit(limits: IterationVmLimits) -> Option<(&'static str, u64, u64)> {
    let vm = limits.capture.vm;
    if vm.max_input_bytes == 0 {
        return Some(("iteration.capture.vm.max_input_bytes", 0, 1));
    }
    if vm.max_threads_per_offset == 0 {
        return Some(("iteration.capture.vm.max_threads_per_offset", 0, 1));
    }
    if vm.max_memory_bytes < ACCOUNTED_VM_BASE_BYTES {
        return Some((
            "iteration.capture.vm.max_memory_bytes",
            vm.max_memory_bytes,
            ACCOUNTED_VM_BASE_BYTES,
        ));
    }
    if vm.max_work_units == 0 {
        return Some(("iteration.capture.vm.max_work_units", 0, 1));
    }
    if vm.max_trace_events == 0 {
        return Some(("iteration.capture.vm.max_trace_events", 0, 1));
    }
    if limits.capture.max_capture_history_nodes == 0 {
        return Some(("iteration.capture.max_capture_history_nodes", 0, 1));
    }
    if limits.max_matches == 0 {
        return Some(("iteration.max_matches", 0, 1));
    }
    if limits.max_trace_events == 0 {
        return Some(("iteration.max_trace_events", 0, 1));
    }
    None
}

impl std::error::Error for PrivatePatternConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.compile_error
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementErrorKind {
    TemplateLimit,
    TokenLimit,
    MalformedReference,
    CaptureIndexOverflow,
    UnknownCapture,
    OutputLimit,
    WorkLimit,
    ArithmeticOverflow,
    InvalidMatchBoundary,
    OverlappingMatch,
    AllocationFailure,
}

impl ReplacementErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::TemplateLimit => "RGX-REPLACE-E001",
            Self::TokenLimit => "RGX-REPLACE-E002",
            Self::MalformedReference => "RGX-REPLACE-E003",
            Self::CaptureIndexOverflow => "RGX-REPLACE-E004",
            Self::UnknownCapture => "RGX-REPLACE-E005",
            Self::OutputLimit => "RGX-REPLACE-E006",
            Self::WorkLimit => "RGX-REPLACE-E007",
            Self::ArithmeticOverflow => "RGX-REPLACE-E008",
            Self::InvalidMatchBoundary => "RGX-REPLACE-E009",
            Self::OverlappingMatch => "RGX-REPLACE-E010",
            Self::AllocationFailure => "RGX-REPLACE-E011",
        }
    }
}

/// Secret-safe replacement failure. Source text and capture names are omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplacementError {
    pub kind: ReplacementErrorKind,
    pub offset: Option<usize>,
    pub actual: Option<u64>,
    pub limit: Option<u64>,
}

impl ReplacementError {
    const fn new(kind: ReplacementErrorKind) -> Self {
        Self {
            kind,
            offset: None,
            actual: None,
            limit: None,
        }
    }

    const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    fn with_actual_limit<A, L>(mut self, actual: A, limit: L) -> Self
    where
        A: TryInto<u64>,
        L: TryInto<u64>,
    {
        self.actual = actual.try_into().ok();
        self.limit = limit.try_into().ok();
        self
    }

    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for ReplacementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{}] regex replacement failed", self.kind.code())?;
        if let Some(offset) = self.offset {
            write!(formatter, " offset={offset}")?;
        }
        if let (Some(actual), Some(limit)) = (self.actual, self.limit) {
            write!(formatter, " actual={actual} limit={limit}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ReplacementError {}

#[derive(Debug)]
pub enum ReplacementOperationError {
    Template(ReplacementError),
    Vm(VmError),
}

impl fmt::Display for ReplacementOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Template(error) => error.fmt(formatter),
            Self::Vm(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ReplacementOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Template(error) => Some(error),
            Self::Vm(error) => Some(error),
        }
    }
}

impl From<ReplacementError> for ReplacementOperationError {
    fn from(error: ReplacementError) -> Self {
        Self::Template(error)
    }
}

impl From<VmError> for ReplacementOperationError {
    fn from(error: VmError) -> Self {
        Self::Vm(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplacementResources {
    pub template_bytes: usize,
    pub tokens: usize,
    pub matches_replaced: usize,
    pub output_bytes: usize,
    pub work_units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacementOutcome {
    pub output: String,
    pub resources: ReplacementResources,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplacementToken<'template> {
    Literal(&'template str),
    Dollar,
    Capture(usize),
    Empty,
}

/// Parsed replacement tokens borrowing the caller-owned template.
///
/// `Debug` intentionally reports only normalized counts so replacement text or
/// capture names cannot leak through diagnostics.
pub struct ReplacementTemplate<'template> {
    tokens: Vec<ReplacementToken<'template>>,
    template_bytes: usize,
    parse_work_units: u64,
}

impl fmt::Debug for ReplacementTemplate<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplacementTemplate")
            .field("template_bytes", &self.template_bytes)
            .field("tokens", &self.tokens.len())
            .field("parse_work_units", &self.parse_work_units)
            .finish()
    }
}

/// Immutable compile-once facade over the private checked compiler and VM.
///
/// The enclosing module is crate-private and compiled only with `metrics`.
/// This type stores validated IR, the exact IR limits used to compile it, and
/// only the capture identifiers required for named replacement references. It
/// never stores the complete source pattern, haystack, capture contents,
/// mutable execution state, or an ambient cache. Every operation receives
/// explicit work and memory limits, and controlled variants receive
/// caller-owned cancellation. Public wiring and incumbent replacement remain
/// separately owned.
pub struct PrivateCompiledPattern {
    program: Program,
    compile_limits: CompileLimits,
    capture_names: Vec<Option<Box<str>>>,
    accounted_capture_metadata_bytes: usize,
}

impl PrivateCompiledPattern {
    /// Compile and validate one pattern for repeated private use.
    pub fn compile(
        pattern: &str,
        limits: PrivateCompileLimits,
    ) -> Result<Self, PrivateCompileError> {
        let output = compile_private_with_captures(pattern, limits)?;
        // Deterministic accounting covers the exact Vec element footprint and
        // retained UTF-8 name bytes, not allocator bookkeeping or slack.
        let accounted_capture_metadata_bytes = output
            .capture_names
            .len()
            .saturating_mul(core::mem::size_of::<Option<Box<str>>>())
            .saturating_add(
                output
                    .capture_names
                    .iter()
                    .flatten()
                    .map(|name| name.len())
                    .sum::<usize>(),
            );
        Ok(Self {
            program: output.program,
            compile_limits: limits.ir,
            capture_names: output.capture_names,
            accounted_capture_metadata_bytes,
        })
    }

    /// Deterministic retained-byte charge for the compiled program and capture
    /// metadata. Allocator bookkeeping and unused capacity are intentionally
    /// outside this logical accounting boundary.
    fn accounted_retained_bytes(&self) -> Option<u64> {
        let capture_metadata = u64::try_from(self.accounted_capture_metadata_bytes).ok()?;
        self.program
            .resources
            .accounted_memory_bytes
            .checked_add(capture_metadata)
    }

    /// Return whether a leftmost-first match exists.
    pub fn is_match(&self, haystack: &str, limits: CaptureVmLimits) -> Result<bool, VmError> {
        self.captures(haystack, limits)
            .map(|matched| matched.is_some())
    }

    /// Return whether a match exists with explicit cooperative cancellation.
    pub fn is_match_with_control(
        &self,
        haystack: &str,
        limits: CaptureVmLimits,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<bool, VmError> {
        self.captures_with_control(haystack, limits, control)
            .map(|matched| matched.is_some())
    }

    /// Select one leftmost-first whole-match span.
    pub fn find(
        &self,
        haystack: &str,
        limits: CaptureVmLimits,
    ) -> Result<Option<CaptureSpan>, VmError> {
        self.captures(haystack, limits)
            .map(|matched| matched.map(|selected| selected.span))
    }

    /// Select one whole-match span with explicit cooperative cancellation.
    pub fn find_with_control(
        &self,
        haystack: &str,
        limits: CaptureVmLimits,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<Option<CaptureSpan>, VmError> {
        self.captures_with_control(haystack, limits, control)
            .map(|matched| matched.map(|selected| selected.span))
    }

    /// Select one leftmost-first match and its participating capture spans.
    pub fn captures(
        &self,
        haystack: &str,
        limits: CaptureVmLimits,
    ) -> Result<Option<VmMatch>, VmError> {
        execute_search(&self.program, haystack, self.compile_limits, limits)
            .map(|outcome| outcome.matched)
    }

    /// Select one match and captures with explicit cooperative cancellation.
    pub fn captures_with_control(
        &self,
        haystack: &str,
        limits: CaptureVmLimits,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<Option<VmMatch>, VmError> {
        execute_search_with_control(
            &self.program,
            haystack,
            self.compile_limits,
            limits,
            control,
        )
        .map(|outcome| outcome.matched)
    }

    /// Iterate matches deterministically under one aggregate resource budget.
    pub fn find_iter(
        &self,
        haystack: &str,
        policy: IterationPolicy,
        limits: IterationVmLimits,
    ) -> Result<VmIterationOutcome, VmError> {
        execute_find_iter(&self.program, haystack, self.compile_limits, policy, limits)
    }

    /// Iterate under one aggregate resource budget and cancellation sequence.
    pub fn find_iter_with_control(
        &self,
        haystack: &str,
        policy: IterationPolicy,
        limits: IterationVmLimits,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<VmIterationOutcome, VmError> {
        execute_find_iter_with_control(
            &self.program,
            haystack,
            self.compile_limits,
            policy,
            limits,
            control,
        )
    }

    /// Parse one incumbent-compatible replacement template without copying it.
    ///
    /// Syntax is deliberately total: malformed-looking `$` sequences remain
    /// literal and unknown references expand to empty, matching `regex` 1.13.
    pub fn parse_replacement<'template>(
        &self,
        template: &'template str,
        limits: ReplacementLimits,
    ) -> Result<ReplacementTemplate<'template>, ReplacementError> {
        ReplacementTemplate::parse(template, &self.capture_names, limits, false)
    }

    /// Parse a replacement template with typed malformed/unknown diagnostics.
    ///
    /// This is an explicit private opt-in and is not used by the compatibility
    /// replacement path.
    pub fn parse_replacement_strict<'template>(
        &self,
        template: &'template str,
        limits: ReplacementLimits,
    ) -> Result<ReplacementTemplate<'template>, ReplacementError> {
        ReplacementTemplate::parse(template, &self.capture_names, limits, true)
    }

    /// Replace every non-overlapping match under explicit aggregate ceilings.
    pub fn replace_all(
        &self,
        haystack: &str,
        template: &str,
        iteration_limits: IterationVmLimits,
        replacement_limits: ReplacementLimits,
    ) -> Result<ReplacementOutcome, ReplacementOperationError> {
        let template = self.parse_replacement(template, replacement_limits)?;
        let matches =
            self.find_iter(haystack, IterationPolicy::NonOverlapping, iteration_limits)?;
        template
            .expand(haystack, &matches, replacement_limits)
            .map_err(Into::into)
    }

    /// Replace with caller-owned cooperative cancellation during match search.
    ///
    /// Template parsing and output emission remain synchronously bounded but
    /// are not cancellation checkpoints; R3.6 owns that broader policy.
    pub fn replace_all_with_match_control(
        &self,
        haystack: &str,
        template: &str,
        iteration_limits: IterationVmLimits,
        replacement_limits: ReplacementLimits,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<ReplacementOutcome, ReplacementOperationError> {
        let template = self.parse_replacement(template, replacement_limits)?;
        let matches = self.find_iter_with_control(
            haystack,
            IterationPolicy::NonOverlapping,
            iteration_limits,
            control,
        )?;
        template
            .expand(haystack, &matches, replacement_limits)
            .map_err(Into::into)
    }
}

impl fmt::Debug for PrivateCompiledPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateCompiledPattern")
            .field("schema_version", &self.program.schema_version)
            .field("ir_id", &self.program.ir_id)
            .field("states", &self.program.resources.states)
            .field("classes", &self.program.resources.classes)
            .field("capture_slots", &self.program.resources.capture_slots)
            .field(
                "named_captures",
                &self.capture_names.iter().flatten().count(),
            )
            .field(
                "program_accounted_memory_bytes",
                &self.program.resources.accounted_memory_bytes,
            )
            .field(
                "accounted_capture_metadata_bytes",
                &self.accounted_capture_metadata_bytes,
            )
            .finish_non_exhaustive()
    }
}

/// Atomically validated private execution limits and compiled program.
///
/// Loading consumes the explicit configuration, copies only its numeric
/// execution limits, and drops the source pattern after compilation. The
/// immutable runtime value therefore cannot return or render the pattern.
pub struct LoadedPrivatePattern {
    compiled: PrivateCompiledPattern,
    iteration_limits: IterationVmLimits,
    replacement_limits: ReplacementLimits,
}

impl LoadedPrivatePattern {
    /// Match with the configured aggregate capture/VM limits.
    pub fn is_match(&self, haystack: &str) -> Result<bool, VmError> {
        self.compiled
            .is_match(haystack, self.iteration_limits.capture)
    }

    /// Match with configured limits and caller-owned cancellation.
    pub fn is_match_with_control(
        &self,
        haystack: &str,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<bool, VmError> {
        self.compiled
            .is_match_with_control(haystack, self.iteration_limits.capture, control)
    }

    /// Find one leftmost-first match with configured limits.
    pub fn find(&self, haystack: &str) -> Result<Option<CaptureSpan>, VmError> {
        self.compiled.find(haystack, self.iteration_limits.capture)
    }

    /// Find with configured limits and caller-owned cancellation.
    pub fn find_with_control(
        &self,
        haystack: &str,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<Option<CaptureSpan>, VmError> {
        self.compiled
            .find_with_control(haystack, self.iteration_limits.capture, control)
    }

    /// Find one match and its participating captures with configured limits.
    pub fn captures(&self, haystack: &str) -> Result<Option<VmMatch>, VmError> {
        self.compiled
            .captures(haystack, self.iteration_limits.capture)
    }

    /// Capture with configured limits and caller-owned cancellation.
    pub fn captures_with_control(
        &self,
        haystack: &str,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<Option<VmMatch>, VmError> {
        self.compiled
            .captures_with_control(haystack, self.iteration_limits.capture, control)
    }

    /// Iterate deterministically with the configured aggregate limits.
    pub fn find_iter(
        &self,
        haystack: &str,
        policy: IterationPolicy,
    ) -> Result<VmIterationOutcome, VmError> {
        self.compiled
            .find_iter(haystack, policy, self.iteration_limits)
    }

    /// Iterate with configured limits and caller-owned cancellation.
    pub fn find_iter_with_control(
        &self,
        haystack: &str,
        policy: IterationPolicy,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<VmIterationOutcome, VmError> {
        self.compiled
            .find_iter_with_control(haystack, policy, self.iteration_limits, control)
    }

    /// Replace every non-overlapping match with the configured ceilings.
    pub fn replace_all(
        &self,
        haystack: &str,
        template: &str,
    ) -> Result<ReplacementOutcome, ReplacementOperationError> {
        self.compiled.replace_all(
            haystack,
            template,
            self.iteration_limits,
            self.replacement_limits,
        )
    }

    /// Replace with configured ceilings and cancellation during match search.
    ///
    /// Template parsing and final output emission remain synchronously bounded
    /// rather than cancellable; this method makes that existing boundary
    /// available through the configured facade without claiming more.
    pub fn replace_all_with_match_control(
        &self,
        haystack: &str,
        template: &str,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<ReplacementOutcome, ReplacementOperationError> {
        self.compiled.replace_all_with_match_control(
            haystack,
            template,
            self.iteration_limits,
            self.replacement_limits,
            control,
        )
    }
}

impl fmt::Debug for LoadedPrivatePattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedPrivatePattern")
            .field("compiled", &self.compiled)
            .field("iteration_limits", &self.iteration_limits)
            .field("replacement_limits", &self.replacement_limits)
            .finish()
    }
}

/// Explicit ceilings for one caller-owned private compiled-pattern cache.
///
/// `max_live_accounted_bytes` includes residents that have been evicted from
/// the cache but remain alive through a caller lease. This prevents eviction
/// from being misreported as memory reclamation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivatePatternCacheLimits {
    pub max_entries: usize,
    pub max_pattern_bytes: usize,
    pub max_live_accounted_bytes: u64,
    pub max_inflight_compiles: usize,
    pub max_inflight_compile_accounted_bytes: u64,
    pub max_lookup_work_units: u64,
}

impl Default for PrivatePatternCacheLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_PRIVATE_PATTERN_CACHE_MAX_ENTRIES,
            max_pattern_bytes: DEFAULT_PRIVATE_PATTERN_CACHE_MAX_PATTERN_BYTES,
            max_live_accounted_bytes: DEFAULT_PRIVATE_PATTERN_CACHE_MAX_LIVE_ACCOUNTED_BYTES,
            max_inflight_compiles: DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILES,
            max_inflight_compile_accounted_bytes:
                DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILE_ACCOUNTED_BYTES,
            max_lookup_work_units: DEFAULT_PRIVATE_PATTERN_CACHE_MAX_LOOKUP_WORK_UNITS,
        }
    }
}

/// Stable, source-text-free failure category for private cache operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivatePatternCacheErrorKind {
    InvalidLimits,
    PatternLimit,
    EntryTooLarge,
    CapacityPinned,
    Closed,
    Cancelled,
    Config,
    AllocationFailure,
    ArithmeticOverflow,
    CompileCapacity,
    CompileMemoryCapacity,
    LookupWorkLimit,
}

impl PrivatePatternCacheErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "RGX-CACHE-E001",
            Self::PatternLimit => "RGX-CACHE-E002",
            Self::EntryTooLarge => "RGX-CACHE-E003",
            Self::CapacityPinned => "RGX-CACHE-E004",
            Self::Closed => "RGX-CACHE-E005",
            Self::Cancelled => "RGX-CACHE-E006",
            Self::Config => "RGX-CACHE-E007",
            Self::AllocationFailure => "RGX-CACHE-E008",
            Self::ArithmeticOverflow => "RGX-CACHE-E009",
            Self::CompileCapacity => "RGX-CACHE-E010",
            Self::CompileMemoryCapacity => "RGX-CACHE-E011",
            Self::LookupWorkLimit => "RGX-CACHE-E012",
        }
    }
}

/// Source-secret-safe cache failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivatePatternCacheError {
    pub kind: PrivatePatternCacheErrorKind,
    pub actual: Option<u64>,
    pub limit: Option<u64>,
    pub config_error: Option<PrivatePatternConfigError>,
}

impl PrivatePatternCacheError {
    const fn new(kind: PrivatePatternCacheErrorKind) -> Self {
        Self {
            kind,
            actual: None,
            limit: None,
            config_error: None,
        }
    }

    const fn config(config_error: PrivatePatternConfigError) -> Self {
        Self {
            kind: PrivatePatternCacheErrorKind::Config,
            actual: None,
            limit: None,
            config_error: Some(config_error),
        }
    }

    fn with_actual_limit<A, L>(mut self, actual: A, limit: L) -> Self
    where
        A: TryInto<u64>,
        L: TryInto<u64>,
    {
        self.actual = actual.try_into().ok();
        self.limit = limit.try_into().ok();
        self
    }

    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for PrivatePatternCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}] private regex cache operation failed",
            self.kind.code()
        )?;
        if let (Some(actual), Some(limit)) = (self.actual, self.limit) {
            write!(formatter, " actual={actual} limit={limit}")?;
        }
        if let Some(config_error) = self.config_error {
            write!(formatter, " config_code={}", config_error.code())?;
        }
        Ok(())
    }
}

impl std::error::Error for PrivatePatternCacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.config_error
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

/// Cancellation point around synchronous cache-miss compilation.
///
/// Compilation itself remains synchronously work-bounded. A cancellation that
/// arrives during compilation is observed at `Admission`, discards the
/// result, and leaves the cache unchanged; this does not claim prompt
/// mid-compiler preemption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivatePatternCacheCheckpoint {
    Lookup,
    Compile,
    Admission,
}

/// Caller-owned cancellation probe with no ambient runtime dependency.
pub trait PrivatePatternCacheCancellationProbe {
    fn should_cancel(&mut self, checkpoint: PrivatePatternCacheCheckpoint) -> bool;
}

impl<F> PrivatePatternCacheCancellationProbe for F
where
    F: FnMut(PrivatePatternCacheCheckpoint) -> bool,
{
    fn should_cancel(&mut self, checkpoint: PrivatePatternCacheCheckpoint) -> bool {
        self(checkpoint)
    }
}

/// Explicit cancellation state for one cache lookup/compile/admission attempt.
pub struct PrivatePatternCacheAdmissionControl<'probe> {
    probe: &'probe mut dyn PrivatePatternCacheCancellationProbe,
    cancelled_at: Option<PrivatePatternCacheCheckpoint>,
}

impl<'probe> PrivatePatternCacheAdmissionControl<'probe> {
    pub fn new(probe: &'probe mut dyn PrivatePatternCacheCancellationProbe) -> Self {
        Self {
            probe,
            cancelled_at: None,
        }
    }

    pub const fn cancelled_at(&self) -> Option<PrivatePatternCacheCheckpoint> {
        self.cancelled_at
    }

    fn check(&mut self, checkpoint: PrivatePatternCacheCheckpoint) -> bool {
        if self.probe.should_cancel(checkpoint) {
            self.cancelled_at = Some(checkpoint);
            true
        } else {
            false
        }
    }
}

impl fmt::Debug for PrivatePatternCacheAdmissionControl<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivatePatternCacheAdmissionControl")
            .field("cancelled_at", &self.cancelled_at)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrivatePatternCacheFingerprint {
    first: u64,
    second: u64,
}

fn private_pattern_cache_fingerprint(pattern: &str) -> PrivatePatternCacheFingerprint {
    let mut first = FINGERPRINT_OFFSET_BASIS;
    let mut second = 0x6c62_272e_07bb_0142_u64;
    for byte in pattern.bytes() {
        first = (first ^ u64::from(byte)).wrapping_mul(FINGERPRINT_PRIME);
        second = (second ^ u64::from(byte).wrapping_add(0x9d))
            .rotate_left(7)
            .wrapping_mul(0x9e37_79b1_85eb_ca87);
    }
    PrivatePatternCacheFingerprint { first, second }
}

/// Collision-safe cache identity.
///
/// The complete source pattern is retained so a digest collision can never
/// select the wrong privacy policy. Its bytes are charged to the live resident,
/// never rendered by diagnostics, and live until the final cache/lease owner is
/// dropped. This is not a memory-erasure or RSS non-retention claim.
#[derive(Clone, PartialEq, Eq)]
struct PrivatePatternCacheKey {
    schema_version: u16,
    pattern: String,
    fingerprint: PrivatePatternCacheFingerprint,
    compile_limits: PrivateCompileLimits,
    iteration_limits: IterationVmLimits,
    replacement_limits: ReplacementLimits,
}

impl PrivatePatternCacheKey {
    fn try_from_config(
        config: &PrivatePatternConfig,
        fingerprint: PrivatePatternCacheFingerprint,
    ) -> Result<Self, PrivatePatternCacheError> {
        let mut pattern = String::new();
        pattern
            .try_reserve_exact(config.pattern.len())
            .map_err(|_| {
                PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::AllocationFailure)
            })?;
        pattern.push_str(&config.pattern);
        Ok(Self {
            schema_version: config.schema_version,
            pattern,
            fingerprint,
            compile_limits: config.compile_limits,
            iteration_limits: config.iteration_limits,
            replacement_limits: config.replacement_limits,
        })
    }

    fn metadata_matches_config(&self, config: &PrivatePatternConfig) -> bool {
        self.schema_version == config.schema_version
            && self.compile_limits == config.compile_limits
            && self.iteration_limits == config.iteration_limits
            && self.replacement_limits == config.replacement_limits
    }

    fn metadata_matches_key(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.compile_limits == other.compile_limits
            && self.iteration_limits == other.iteration_limits
            && self.replacement_limits == other.replacement_limits
    }
}

impl fmt::Debug for PrivatePatternCacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivatePatternCacheKey")
            .field("schema_version", &self.schema_version)
            .field("pattern_bytes", &self.pattern.len())
            .field("compile_limits", &self.compile_limits)
            .field("iteration_limits", &self.iteration_limits)
            .field("replacement_limits", &self.replacement_limits)
            .finish()
    }
}

struct ResidentPrivatePattern {
    key: PrivatePatternCacheKey,
    loaded: LoadedPrivatePattern,
    accounted_live_bytes: u64,
    live_accounted_bytes: Arc<AtomicU64>,
    charged: AtomicBool,
}

impl Drop for ResidentPrivatePattern {
    fn drop(&mut self) {
        if self.charged.swap(false, Ordering::AcqRel) {
            let previous = self
                .live_accounted_bytes
                .fetch_sub(self.accounted_live_bytes, Ordering::AcqRel);
            debug_assert!(previous >= self.accounted_live_bytes);
        }
    }
}

/// Immutable caller lease for one configured private pattern.
///
/// Eviction or cache shutdown removes only the cache's ownership. Existing
/// leases remain valid and remain charged against the cache's live-byte
/// ceiling until their final clone is dropped.
#[derive(Clone)]
pub struct PrivatePatternLease {
    resident: Arc<ResidentPrivatePattern>,
}

impl PrivatePatternLease {
    pub fn accounted_live_bytes(&self) -> u64 {
        self.resident.accounted_live_bytes
    }

    pub fn is_match(&self, haystack: &str) -> Result<bool, VmError> {
        self.resident.loaded.is_match(haystack)
    }

    pub fn is_match_with_control(
        &self,
        haystack: &str,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<bool, VmError> {
        self.resident
            .loaded
            .is_match_with_control(haystack, control)
    }

    pub fn find(&self, haystack: &str) -> Result<Option<CaptureSpan>, VmError> {
        self.resident.loaded.find(haystack)
    }

    pub fn find_with_control(
        &self,
        haystack: &str,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<Option<CaptureSpan>, VmError> {
        self.resident.loaded.find_with_control(haystack, control)
    }

    pub fn captures(&self, haystack: &str) -> Result<Option<VmMatch>, VmError> {
        self.resident.loaded.captures(haystack)
    }

    pub fn captures_with_control(
        &self,
        haystack: &str,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<Option<VmMatch>, VmError> {
        self.resident
            .loaded
            .captures_with_control(haystack, control)
    }

    pub fn find_iter(
        &self,
        haystack: &str,
        policy: IterationPolicy,
    ) -> Result<VmIterationOutcome, VmError> {
        self.resident.loaded.find_iter(haystack, policy)
    }

    pub fn find_iter_with_control(
        &self,
        haystack: &str,
        policy: IterationPolicy,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<VmIterationOutcome, VmError> {
        self.resident
            .loaded
            .find_iter_with_control(haystack, policy, control)
    }

    pub fn replace_all(
        &self,
        haystack: &str,
        template: &str,
    ) -> Result<ReplacementOutcome, ReplacementOperationError> {
        self.resident.loaded.replace_all(haystack, template)
    }

    pub fn replace_all_with_match_control(
        &self,
        haystack: &str,
        template: &str,
        control: &mut VmCancellationControl<'_>,
    ) -> Result<ReplacementOutcome, ReplacementOperationError> {
        self.resident
            .loaded
            .replace_all_with_match_control(haystack, template, control)
    }
}

impl fmt::Debug for PrivatePatternLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivatePatternLease")
            .field("key", &self.resident.key)
            .field("accounted_live_bytes", &self.resident.accounted_live_bytes)
            .field("loaded", &self.resident.loaded)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivatePatternCacheSnapshot {
    pub closed: bool,
    pub entries: usize,
    pub cache_owned_accounted_bytes: u64,
    pub live_accounted_bytes: u64,
    pub inflight_compiles: usize,
    pub inflight_compile_accounted_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub compilations: u64,
    pub admissions: u64,
    pub duplicate_compiles: u64,
    pub evictions: u64,
    pub clears: u64,
}

struct PrivatePatternCacheEntry {
    resident: Arc<ResidentPrivatePattern>,
}

struct PrivatePatternCacheState {
    entries: Vec<PrivatePatternCacheEntry>,
    closed: bool,
    hits: u64,
    misses: u64,
    compilations: u64,
    admissions: u64,
    duplicate_compiles: u64,
    evictions: u64,
    clears: u64,
}

fn checked_compile_component(count: usize, bytes_per_item: u64) -> Option<u64> {
    u64::try_from(count).ok()?.checked_mul(bytes_per_item)
}

/// Conservative logical reservation derived from every compile-stage ceiling.
///
/// These charges intentionally exceed the schema element sizes used by the
/// retained IR. They bound concurrent cache-miss compilation policy; they are
/// not allocator-usable-size or RSS measurements.
fn private_pattern_compile_reservation_bytes(
    config: &PrivatePatternConfig,
) -> Result<u64, PrivatePatternCacheError> {
    let limits = config.compile_limits;
    let components = [
        checked_compile_component(config.pattern.len(), ACCOUNTED_PRIVATE_PATTERN_SOURCE_BYTE),
        checked_compile_component(
            limits.lexer.max_tokens,
            ACCOUNTED_PRIVATE_PATTERN_TOKEN_BYTES,
        ),
        checked_compile_component(
            limits.parser.max_ast_nodes,
            ACCOUNTED_PRIVATE_PATTERN_AST_NODE_BYTES,
        ),
        checked_compile_component(
            limits.semantic.max_semantic_atoms,
            ACCOUNTED_PRIVATE_PATTERN_SEMANTIC_ATOM_BYTES,
        ),
        checked_compile_component(
            limits.semantic.max_total_ranges,
            ACCOUNTED_PRIVATE_PATTERN_RANGE_BYTES,
        ),
        checked_compile_component(
            limits.fold_boundary.max_fold_atoms,
            ACCOUNTED_PRIVATE_PATTERN_FOLD_ATOM_BYTES,
        ),
        checked_compile_component(
            limits.fold_boundary.max_total_fold_ranges,
            ACCOUNTED_PRIVATE_PATTERN_RANGE_BYTES,
        ),
        checked_compile_component(
            limits.fold_boundary.max_boundary_assertions,
            ACCOUNTED_PRIVATE_PATTERN_BOUNDARY_BYTES,
        ),
        Some(limits.ir.max_memory_bytes),
    ];
    components
        .into_iter()
        .try_fold(
            ACCOUNTED_PRIVATE_PATTERN_COMPILE_BASE_BYTES,
            |total, component| total.checked_add(component?),
        )
        .ok_or_else(|| {
            PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
        })
}

fn charge_private_pattern_lookup_work(
    work_units: &mut u64,
    units: u64,
    limit: u64,
) -> Result<(), PrivatePatternCacheError> {
    let next = work_units.checked_add(units).ok_or_else(|| {
        PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
    })?;
    if next > limit {
        return Err(
            PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::LookupWorkLimit)
                .with_actual_limit(next, limit),
        );
    }
    *work_units = next;
    Ok(())
}

fn find_private_pattern_config_entry(
    state: &PrivatePatternCacheState,
    config: &PrivatePatternConfig,
    fingerprint: PrivatePatternCacheFingerprint,
    work_units: &mut u64,
    work_limit: u64,
) -> Result<Option<usize>, PrivatePatternCacheError> {
    for (index, entry) in state.entries.iter().enumerate() {
        charge_private_pattern_lookup_work(
            work_units,
            ACCOUNTED_PRIVATE_PATTERN_LOOKUP_ENTRY_WORK_UNITS,
            work_limit,
        )?;
        let key = &entry.resident.key;
        if key.fingerprint != fingerprint || !key.metadata_matches_config(config) {
            continue;
        }
        let exact_bytes = config
            .pattern
            .len()
            .checked_add(key.pattern.len())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
            })?;
        charge_private_pattern_lookup_work(work_units, exact_bytes, work_limit)?;
        if key.pattern == config.pattern {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn find_private_pattern_key_entry(
    state: &PrivatePatternCacheState,
    candidate: &PrivatePatternCacheKey,
    work_units: &mut u64,
    work_limit: u64,
) -> Result<Option<usize>, PrivatePatternCacheError> {
    for (index, entry) in state.entries.iter().enumerate() {
        charge_private_pattern_lookup_work(
            work_units,
            ACCOUNTED_PRIVATE_PATTERN_LOOKUP_ENTRY_WORK_UNITS,
            work_limit,
        )?;
        let key = &entry.resident.key;
        if key.fingerprint != candidate.fingerprint || !key.metadata_matches_key(candidate) {
            continue;
        }
        let exact_bytes = candidate
            .pattern
            .len()
            .checked_add(key.pattern.len())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
            })?;
        charge_private_pattern_lookup_work(work_units, exact_bytes, work_limit)?;
        if key.pattern == candidate.pattern {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// Caller-owned bounded LRU cache for configured private patterns.
///
/// The cache has no global instance and starts no tasks or obligations.
/// Compilation and cancellation callbacks always run outside its mutex. A
/// concurrent miss may compile redundantly; admission rechecks exact key
/// equality and retains one deterministic winner.
pub struct PrivatePatternCache {
    limits: PrivatePatternCacheLimits,
    state: Mutex<PrivatePatternCacheState>,
    live_accounted_bytes: Arc<AtomicU64>,
    compile_accounting: Mutex<PrivatePatternCompileAccounting>,
}

struct PrivatePatternCompileAccounting {
    inflight_compiles: usize,
    inflight_compile_accounted_bytes: u64,
}

struct PrivatePatternCompilePermit<'cache> {
    compile_accounting: &'cache Mutex<PrivatePatternCompileAccounting>,
    accounted_bytes: u64,
}

impl Drop for PrivatePatternCompilePermit<'_> {
    fn drop(&mut self) {
        let mut accounting = self.compile_accounting.lock();
        debug_assert!(accounting.inflight_compiles > 0);
        debug_assert!(accounting.inflight_compile_accounted_bytes >= self.accounted_bytes);
        accounting.inflight_compiles = accounting.inflight_compiles.saturating_sub(1);
        accounting.inflight_compile_accounted_bytes = accounting
            .inflight_compile_accounted_bytes
            .saturating_sub(self.accounted_bytes);
    }
}

impl PrivatePatternCache {
    pub fn new(limits: PrivatePatternCacheLimits) -> Result<Self, PrivatePatternCacheError> {
        if limits.max_entries == 0
            || limits.max_pattern_bytes == 0
            || limits.max_inflight_compiles == 0
            || limits.max_inflight_compile_accounted_bytes == 0
            || limits.max_lookup_work_units == 0
            || limits.max_live_accounted_bytes < ACCOUNTED_PRIVATE_PATTERN_RESIDENT_OVERHEAD_BYTES
        {
            return Err(PrivatePatternCacheError::new(
                PrivatePatternCacheErrorKind::InvalidLimits,
            ));
        }
        let mut entries = Vec::new();
        entries.try_reserve_exact(limits.max_entries).map_err(|_| {
            PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::AllocationFailure)
        })?;
        Ok(Self {
            limits,
            state: Mutex::new(PrivatePatternCacheState {
                entries,
                closed: false,
                hits: 0,
                misses: 0,
                compilations: 0,
                admissions: 0,
                duplicate_compiles: 0,
                evictions: 0,
                clears: 0,
            }),
            live_accounted_bytes: Arc::new(AtomicU64::new(0)),
            compile_accounting: Mutex::new(PrivatePatternCompileAccounting {
                inflight_compiles: 0,
                inflight_compile_accounted_bytes: 0,
            }),
        })
    }

    fn acquire_compile_permit(
        &self,
        accounted_bytes: u64,
    ) -> Result<PrivatePatternCompilePermit<'_>, PrivatePatternCacheError> {
        let mut accounting = self.compile_accounting.lock();
        let requested_compiles = accounting.inflight_compiles.checked_add(1).ok_or_else(|| {
            PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
        })?;
        if requested_compiles > self.limits.max_inflight_compiles {
            return Err(PrivatePatternCacheError::new(
                PrivatePatternCacheErrorKind::CompileCapacity,
            )
            .with_actual_limit(requested_compiles, self.limits.max_inflight_compiles));
        }
        let requested_bytes = accounting
            .inflight_compile_accounted_bytes
            .checked_add(accounted_bytes)
            .ok_or_else(|| {
                PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
            })?;
        if requested_bytes > self.limits.max_inflight_compile_accounted_bytes {
            return Err(PrivatePatternCacheError::new(
                PrivatePatternCacheErrorKind::CompileMemoryCapacity,
            )
            .with_actual_limit(
                requested_bytes,
                self.limits.max_inflight_compile_accounted_bytes,
            ));
        }
        accounting.inflight_compiles = requested_compiles;
        accounting.inflight_compile_accounted_bytes = requested_bytes;
        Ok(PrivatePatternCompilePermit {
            compile_accounting: &self.compile_accounting,
            accounted_bytes,
        })
    }

    pub fn get_or_compile(
        &self,
        config: PrivatePatternConfig,
    ) -> Result<PrivatePatternLease, PrivatePatternCacheError> {
        self.get_or_compile_inner(config, None)
    }

    pub fn get_or_compile_with_admission_control(
        &self,
        config: PrivatePatternConfig,
        control: &mut PrivatePatternCacheAdmissionControl<'_>,
    ) -> Result<PrivatePatternLease, PrivatePatternCacheError> {
        self.get_or_compile_inner(config, Some(control))
    }

    fn get_or_compile_inner(
        &self,
        config: PrivatePatternConfig,
        mut control: Option<&mut PrivatePatternCacheAdmissionControl<'_>>,
    ) -> Result<PrivatePatternLease, PrivatePatternCacheError> {
        {
            let state = self.state.lock();
            if state.closed {
                return Err(PrivatePatternCacheError::new(
                    PrivatePatternCacheErrorKind::Closed,
                ));
            }
            if config.pattern.len() > self.limits.max_pattern_bytes {
                return Err(PrivatePatternCacheError::new(
                    PrivatePatternCacheErrorKind::PatternLimit,
                )
                .with_actual_limit(config.pattern.len(), self.limits.max_pattern_bytes));
            }
        }

        if control
            .as_deref_mut()
            .is_some_and(|control| control.check(PrivatePatternCacheCheckpoint::Lookup))
        {
            return Err(PrivatePatternCacheError::new(
                PrivatePatternCacheErrorKind::Cancelled,
            ));
        }

        let mut lookup_work_units = u64::try_from(config.pattern.len()).map_err(|_| {
            PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
        })?;
        if lookup_work_units > self.limits.max_lookup_work_units {
            return Err(PrivatePatternCacheError::new(
                PrivatePatternCacheErrorKind::LookupWorkLimit,
            )
            .with_actual_limit(lookup_work_units, self.limits.max_lookup_work_units));
        }
        let fingerprint = private_pattern_cache_fingerprint(&config.pattern);

        {
            let mut state = self.state.lock();
            if state.closed {
                return Err(PrivatePatternCacheError::new(
                    PrivatePatternCacheErrorKind::Closed,
                ));
            }
            if let Some(index) = find_private_pattern_config_entry(
                &state,
                &config,
                fingerprint,
                &mut lookup_work_units,
                self.limits.max_lookup_work_units,
            )? {
                let entry = state.entries.remove(index);
                state.entries.push(entry);
                state.hits = state.hits.saturating_add(1);
                return Ok(PrivatePatternLease {
                    resident: Arc::clone(&state.entries.last().expect("moved cache hit").resident),
                });
            }
            state.misses = state.misses.saturating_add(1);
        }

        if control
            .as_deref_mut()
            .is_some_and(|control| control.check(PrivatePatternCacheCheckpoint::Compile))
        {
            return Err(PrivatePatternCacheError::new(
                PrivatePatternCacheErrorKind::Cancelled,
            ));
        }

        let compile_reservation = private_pattern_compile_reservation_bytes(&config)?;
        let _compile_permit = self.acquire_compile_permit(compile_reservation)?;
        let key = PrivatePatternCacheKey::try_from_config(&config, fingerprint)?;
        let loaded =
            PrivatePatternConfig::load(config).map_err(PrivatePatternCacheError::config)?;
        let retained_pattern_bytes = u64::try_from(key.pattern.len()).map_err(|_| {
            PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
        })?;
        let compiled_bytes = loaded.compiled.accounted_retained_bytes().ok_or_else(|| {
            PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
        })?;
        let accounted_live_bytes = ACCOUNTED_PRIVATE_PATTERN_RESIDENT_OVERHEAD_BYTES
            .checked_add(retained_pattern_bytes)
            .and_then(|bytes| bytes.checked_add(compiled_bytes))
            .ok_or_else(|| {
                PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
            })?;

        {
            let mut state = self.state.lock();
            state.compilations = state.compilations.saturating_add(1);
        }

        if accounted_live_bytes > self.limits.max_live_accounted_bytes {
            return Err(
                PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::EntryTooLarge)
                    .with_actual_limit(accounted_live_bytes, self.limits.max_live_accounted_bytes),
            );
        }

        let resident = Arc::new(ResidentPrivatePattern {
            key,
            loaded,
            accounted_live_bytes,
            live_accounted_bytes: Arc::clone(&self.live_accounted_bytes),
            charged: AtomicBool::new(false),
        });

        if control.is_some_and(|control| control.check(PrivatePatternCacheCheckpoint::Admission)) {
            return Err(PrivatePatternCacheError::new(
                PrivatePatternCacheErrorKind::Cancelled,
            ));
        }

        let mut state = self.state.lock();
        if state.closed {
            return Err(PrivatePatternCacheError::new(
                PrivatePatternCacheErrorKind::Closed,
            ));
        }
        if let Some(index) = find_private_pattern_key_entry(
            &state,
            &resident.key,
            &mut lookup_work_units,
            self.limits.max_lookup_work_units,
        )? {
            let entry = state.entries.remove(index);
            state.entries.push(entry);
            state.duplicate_compiles = state.duplicate_compiles.saturating_add(1);
            return Ok(PrivatePatternLease {
                resident: Arc::clone(
                    &state
                        .entries
                        .last()
                        .expect("moved duplicate winner")
                        .resident,
                ),
            });
        }

        let live_before = self.live_accounted_bytes.load(Ordering::Acquire);
        let mut projected_live =
            live_before
                .checked_add(accounted_live_bytes)
                .ok_or_else(|| {
                    PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
                })?;
        let mut projected_entries = state.entries.len().checked_add(1).ok_or_else(|| {
            PrivatePatternCacheError::new(PrivatePatternCacheErrorKind::ArithmeticOverflow)
        })?;
        let mut victim_count = 0_usize;
        while projected_entries > self.limits.max_entries
            || projected_live > self.limits.max_live_accounted_bytes
        {
            let Some(victim) = state.entries.get(victim_count) else {
                return Err(PrivatePatternCacheError::new(
                    PrivatePatternCacheErrorKind::CapacityPinned,
                )
                .with_actual_limit(projected_live, self.limits.max_live_accounted_bytes));
            };
            projected_entries -= 1;
            if Arc::strong_count(&victim.resident) == 1 {
                projected_live =
                    projected_live.saturating_sub(victim.resident.accounted_live_bytes);
            }
            victim_count += 1;
        }

        if victim_count > 0 {
            for victim in state.entries.drain(..victim_count) {
                drop(victim);
            }
            state.evictions = state
                .evictions
                .saturating_add(u64::try_from(victim_count).unwrap_or(u64::MAX));
        }

        let live_after_eviction = self.live_accounted_bytes.load(Ordering::Acquire);
        debug_assert!(
            live_after_eviction
                .checked_add(accounted_live_bytes)
                .is_some_and(|bytes| bytes <= self.limits.max_live_accounted_bytes)
        );
        resident.charged.store(true, Ordering::Release);
        self.live_accounted_bytes
            .fetch_add(accounted_live_bytes, Ordering::AcqRel);
        state.entries.push(PrivatePatternCacheEntry {
            resident: Arc::clone(&resident),
        });
        state.admissions = state.admissions.saturating_add(1);
        Ok(PrivatePatternLease { resident })
    }

    /// Remove every cache-owned entry without invalidating active leases.
    pub fn clear(&self) {
        let mut state = self.state.lock();
        let removed = state.entries.len();
        state.entries.clear();
        state.evictions = state
            .evictions
            .saturating_add(u64::try_from(removed).unwrap_or(u64::MAX));
        state.clears = state.clears.saturating_add(1);
    }

    /// Close admission and remove every cache-owned entry atomically.
    ///
    /// This operation is idempotent. It starts no background cleanup; live
    /// bytes converge to zero synchronously when outstanding leases are
    /// dropped.
    pub fn shutdown(&self) {
        let mut state = self.state.lock();
        if state.closed {
            return;
        }
        state.closed = true;
        let removed = state.entries.len();
        state.entries.clear();
        state.evictions = state
            .evictions
            .saturating_add(u64::try_from(removed).unwrap_or(u64::MAX));
    }

    pub fn snapshot(&self) -> PrivatePatternCacheSnapshot {
        let state = self.state.lock();
        let compile_accounting = self.compile_accounting.lock();
        let cache_owned_accounted_bytes = state.entries.iter().fold(0_u64, |bytes, entry| {
            bytes.saturating_add(entry.resident.accounted_live_bytes)
        });
        PrivatePatternCacheSnapshot {
            closed: state.closed,
            entries: state.entries.len(),
            cache_owned_accounted_bytes,
            live_accounted_bytes: self.live_accounted_bytes.load(Ordering::Acquire),
            inflight_compiles: compile_accounting.inflight_compiles,
            inflight_compile_accounted_bytes: compile_accounting.inflight_compile_accounted_bytes,
            hits: state.hits,
            misses: state.misses,
            compilations: state.compilations,
            admissions: state.admissions,
            duplicate_compiles: state.duplicate_compiles,
            evictions: state.evictions,
            clears: state.clears,
        }
    }
}

impl fmt::Debug for PrivatePatternCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivatePatternCache")
            .field("limits", &self.limits)
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl<'template> ReplacementTemplate<'template> {
    fn parse(
        template: &'template str,
        capture_names: &[Option<Box<str>>],
        limits: ReplacementLimits,
        strict: bool,
    ) -> Result<Self, ReplacementError> {
        if template.len() > limits.max_template_bytes {
            return Err(ReplacementError::new(ReplacementErrorKind::TemplateLimit)
                .with_actual_limit(template.len(), limits.max_template_bytes));
        }
        let parse_work_units = u64::try_from(template.len())
            .map_err(|_| ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow))?;
        if parse_work_units > limits.max_work_units {
            return Err(ReplacementError::new(ReplacementErrorKind::WorkLimit)
                .with_actual_limit(parse_work_units, limits.max_work_units));
        }

        let mut tokens = Vec::new();
        let mut literal_start = 0_usize;
        let mut cursor = 0_usize;
        while cursor < template.len() {
            let Some(relative) = template[cursor..].find('$') else {
                break;
            };
            let dollar = cursor
                .checked_add(relative)
                .ok_or_else(|| ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow))?;
            push_literal_token(
                &mut tokens,
                &template[literal_start..dollar],
                limits.max_tokens,
            )?;

            let after_dollar = dollar
                .checked_add(1)
                .ok_or_else(|| ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow))?;
            if template.as_bytes().get(after_dollar) == Some(&b'$') {
                push_replacement_token(&mut tokens, ReplacementToken::Dollar, limits.max_tokens)?;
                cursor = after_dollar.checked_add(1).ok_or_else(|| {
                    ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow)
                })?;
                literal_start = cursor;
                continue;
            }

            let parsed = if template.as_bytes().get(after_dollar) == Some(&b'{') {
                let reference_start = after_dollar.checked_add(1).ok_or_else(|| {
                    ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow)
                })?;
                match template[reference_start..].find('}') {
                    Some(relative_end) => {
                        let reference_end =
                            reference_start.checked_add(relative_end).ok_or_else(|| {
                                ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow)
                            })?;
                        let consumed_end = reference_end.checked_add(1).ok_or_else(|| {
                            ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow)
                        })?;
                        Some((&template[reference_start..reference_end], consumed_end))
                    }
                    None => None,
                }
            } else {
                let mut reference_end = after_dollar;
                while template
                    .as_bytes()
                    .get(reference_end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    reference_end += 1;
                }
                (reference_end > after_dollar)
                    .then(|| (&template[after_dollar..reference_end], reference_end))
            };

            let Some((reference, reference_end)) = parsed else {
                if strict {
                    return Err(
                        ReplacementError::new(ReplacementErrorKind::MalformedReference)
                            .with_offset(dollar),
                    );
                }
                // The incumbent grammar is total. Preserve this dollar as a
                // literal and continue scanning the remaining template.
                literal_start = dollar;
                cursor = after_dollar;
                continue;
            };

            let token = resolve_replacement_reference(reference, capture_names, strict, dollar)?;
            push_replacement_token(&mut tokens, token, limits.max_tokens)?;
            cursor = reference_end;
            literal_start = cursor;
        }
        push_literal_token(&mut tokens, &template[literal_start..], limits.max_tokens)?;
        Ok(Self {
            tokens,
            template_bytes: template.len(),
            parse_work_units,
        })
    }

    /// Expand this parsed template over ordered non-overlapping matches.
    pub fn expand(
        &self,
        haystack: &str,
        iterated: &VmIterationOutcome,
        limits: ReplacementLimits,
    ) -> Result<ReplacementOutcome, ReplacementError> {
        if self.template_bytes > limits.max_template_bytes {
            return Err(ReplacementError::new(ReplacementErrorKind::TemplateLimit)
                .with_actual_limit(self.template_bytes, limits.max_template_bytes));
        }
        if self.tokens.len() > limits.max_tokens {
            return Err(ReplacementError::new(ReplacementErrorKind::TokenLimit)
                .with_actual_limit(self.tokens.len(), limits.max_tokens));
        }
        if self.parse_work_units > limits.max_work_units {
            return Err(ReplacementError::new(ReplacementErrorKind::WorkLimit)
                .with_actual_limit(self.parse_work_units, limits.max_work_units));
        }

        let mut work_units = self.parse_work_units;
        let mut output_bytes = 0_usize;
        let mut cursor = 0_usize;
        for matched in &iterated.matches {
            charge_replacement_work(&mut work_units, 1, limits.max_work_units)?;
            validate_replacement_span(haystack, matched.span)?;
            if matched.span.start < cursor {
                return Err(
                    ReplacementError::new(ReplacementErrorKind::OverlappingMatch)
                        .with_offset(matched.span.start),
                );
            }
            account_replacement_output(
                &mut output_bytes,
                &haystack[cursor..matched.span.start],
                limits,
                &mut work_units,
            )?;
            for token in &self.tokens {
                charge_replacement_work(&mut work_units, 1, limits.max_work_units)?;
                let value = replacement_token_value(haystack, matched, *token)?;
                if let Some(value) = value {
                    account_replacement_output(&mut output_bytes, value, limits, &mut work_units)?;
                }
            }
            cursor = matched.span.end;
        }
        account_replacement_output(
            &mut output_bytes,
            &haystack[cursor..],
            limits,
            &mut work_units,
        )?;

        let emission_work_units = work_units
            .checked_sub(self.parse_work_units)
            .ok_or_else(|| ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow))?;
        charge_replacement_work(&mut work_units, emission_work_units, limits.max_work_units)?;

        // All indexing, arithmetic, work, and output ceilings are now proven.
        // Allocate exactly once so no partial output exists even internally on
        // a checked failure.
        let mut output = String::new();
        output
            .try_reserve_exact(output_bytes)
            .map_err(|_| ReplacementError::new(ReplacementErrorKind::AllocationFailure))?;
        cursor = 0;
        for matched in &iterated.matches {
            output.push_str(&haystack[cursor..matched.span.start]);
            for token in &self.tokens {
                if let Some(value) = replacement_token_value(haystack, matched, *token)? {
                    output.push_str(value);
                }
            }
            cursor = matched.span.end;
        }
        output.push_str(&haystack[cursor..]);
        debug_assert_eq!(output.len(), output_bytes);
        Ok(ReplacementOutcome {
            resources: ReplacementResources {
                template_bytes: self.template_bytes,
                tokens: self.tokens.len(),
                matches_replaced: iterated.matches.len(),
                output_bytes,
                work_units,
            },
            output,
        })
    }
}

fn push_literal_token<'template>(
    tokens: &mut Vec<ReplacementToken<'template>>,
    literal: &'template str,
    max_tokens: usize,
) -> Result<(), ReplacementError> {
    if literal.is_empty() {
        return Ok(());
    }
    push_replacement_token(tokens, ReplacementToken::Literal(literal), max_tokens)
}

fn push_replacement_token<'template>(
    tokens: &mut Vec<ReplacementToken<'template>>,
    token: ReplacementToken<'template>,
    max_tokens: usize,
) -> Result<(), ReplacementError> {
    let next = tokens
        .len()
        .checked_add(1)
        .ok_or_else(|| ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow))?;
    if next > max_tokens {
        return Err(ReplacementError::new(ReplacementErrorKind::TokenLimit)
            .with_actual_limit(next, max_tokens));
    }
    tokens
        .try_reserve(1)
        .map_err(|_| ReplacementError::new(ReplacementErrorKind::AllocationFailure))?;
    tokens.push(token);
    Ok(())
}

fn resolve_replacement_reference<'template>(
    reference: &str,
    capture_names: &[Option<Box<str>>],
    strict: bool,
    offset: usize,
) -> Result<ReplacementToken<'template>, ReplacementError> {
    let numeric = !reference.is_empty() && reference.bytes().all(|byte| byte.is_ascii_digit());
    if numeric {
        let index = match reference.parse::<usize>() {
            Ok(index) => index,
            Err(_) if strict => {
                return Err(
                    ReplacementError::new(ReplacementErrorKind::CaptureIndexOverflow)
                        .with_offset(offset),
                );
            }
            Err(_) => return Ok(ReplacementToken::Empty),
        };
        if index <= capture_names.len() {
            return Ok(ReplacementToken::Capture(index));
        }
        if strict {
            return Err(ReplacementError::new(ReplacementErrorKind::UnknownCapture)
                .with_offset(offset)
                .with_actual_limit(index, capture_names.len()));
        }
        return Ok(ReplacementToken::Empty);
    }

    if strict && !valid_replacement_capture_name(reference) {
        return Err(
            ReplacementError::new(ReplacementErrorKind::MalformedReference).with_offset(offset),
        );
    }
    let index = capture_names
        .iter()
        .position(|name| name.as_deref() == Some(reference))
        .and_then(|index| index.checked_add(1));
    match index {
        Some(index) => Ok(ReplacementToken::Capture(index)),
        None if strict => {
            Err(ReplacementError::new(ReplacementErrorKind::UnknownCapture).with_offset(offset))
        }
        None => Ok(ReplacementToken::Empty),
    }
}

fn valid_replacement_capture_name(reference: &str) -> bool {
    let mut chars = reference.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_alphabetic())
        && chars.all(|value| value == '_' || value.is_alphanumeric())
}

fn validate_replacement_span(haystack: &str, span: CaptureSpan) -> Result<(), ReplacementError> {
    if span.start > span.end
        || span.end > haystack.len()
        || !haystack.is_char_boundary(span.start)
        || !haystack.is_char_boundary(span.end)
    {
        return Err(
            ReplacementError::new(ReplacementErrorKind::InvalidMatchBoundary)
                .with_offset(span.start),
        );
    }
    Ok(())
}

fn replacement_token_value<'haystack>(
    haystack: &'haystack str,
    matched: &VmMatch,
    token: ReplacementToken<'haystack>,
) -> Result<Option<&'haystack str>, ReplacementError> {
    match token {
        ReplacementToken::Literal(value) => Ok(Some(value)),
        ReplacementToken::Dollar => Ok(Some("$")),
        ReplacementToken::Empty => Ok(None),
        ReplacementToken::Capture(0) => Ok(Some(&haystack[matched.span.start..matched.span.end])),
        ReplacementToken::Capture(index) => {
            let capture = matched.captures.get(index - 1).copied().flatten();
            let Some(span) = capture else {
                return Ok(None);
            };
            validate_replacement_span(haystack, span)?;
            if span.start < matched.span.start || span.end > matched.span.end {
                return Err(
                    ReplacementError::new(ReplacementErrorKind::InvalidMatchBoundary)
                        .with_offset(span.start),
                );
            }
            Ok(Some(&haystack[span.start..span.end]))
        }
    }
}

fn account_replacement_output(
    output_bytes: &mut usize,
    value: &str,
    limits: ReplacementLimits,
    work_units: &mut u64,
) -> Result<(), ReplacementError> {
    let next = output_bytes
        .checked_add(value.len())
        .ok_or_else(|| ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow))?;
    if next > limits.max_output_bytes {
        return Err(ReplacementError::new(ReplacementErrorKind::OutputLimit)
            .with_actual_limit(next, limits.max_output_bytes));
    }
    let bytes = u64::try_from(value.len())
        .map_err(|_| ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow))?;
    charge_replacement_work(work_units, bytes, limits.max_work_units)?;
    *output_bytes = next;
    Ok(())
}

fn charge_replacement_work(
    work_units: &mut u64,
    units: u64,
    limit: u64,
) -> Result<(), ReplacementError> {
    let next = work_units
        .checked_add(units)
        .ok_or_else(|| ReplacementError::new(ReplacementErrorKind::ArithmeticOverflow))?;
    if next > limit {
        return Err(
            ReplacementError::new(ReplacementErrorKind::WorkLimit).with_actual_limit(next, limit)
        );
    }
    *work_units = next;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmErrorKind {
    Compile(CompileErrorKind),
    Boundary(BoundaryEvalErrorKind),
    InvalidLimits,
    InputLimit,
    ThreadLimit,
    MemoryLimit,
    WorkLimit,
    ArithmeticOverflow,
    InvalidState,
    InvalidClass,
    BucketCollision,
    CaptureHistoryLimit,
    InvalidCaptureHistory,
    InvalidCaptureBoundary,
    MatchLimit,
    InvalidIterationBoundary,
    Cancelled,
}

impl VmErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Compile(kind) => kind.code(),
            Self::Boundary(kind) => kind.code(),
            Self::InvalidLimits => "RGX-VM-E001",
            Self::InputLimit => "RGX-VM-E002",
            Self::ThreadLimit => "RGX-VM-E003",
            Self::MemoryLimit => "RGX-VM-E004",
            Self::WorkLimit => "RGX-VM-E005",
            Self::ArithmeticOverflow => "RGX-VM-E006",
            Self::InvalidState => "RGX-VM-E007",
            Self::InvalidClass => "RGX-VM-E008",
            Self::BucketCollision => "RGX-VM-E009",
            Self::CaptureHistoryLimit => "RGX-VM-E010",
            Self::InvalidCaptureHistory => "RGX-VM-E011",
            Self::InvalidCaptureBoundary => "RGX-VM-E012",
            Self::MatchLimit => "RGX-VM-E013",
            Self::InvalidIterationBoundary => "RGX-VM-E014",
            Self::Cancelled => "RGX-VM-E015",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmError {
    pub kind: VmErrorKind,
    pub offset: Option<usize>,
    pub state: Option<StateId>,
    pub class: Option<ClassId>,
    pub actual: Option<u64>,
    pub limit: Option<u64>,
}

impl VmError {
    const fn new(kind: VmErrorKind) -> Self {
        Self {
            kind,
            offset: None,
            state: None,
            class: None,
            actual: None,
            limit: None,
        }
    }

    fn compile(error: CompileError) -> Self {
        Self {
            kind: VmErrorKind::Compile(error.kind),
            offset: None,
            state: error.state,
            class: error.class,
            actual: error.actual,
            limit: error.limit,
        }
    }

    const fn boundary(kind: BoundaryEvalErrorKind, offset: usize, state: StateId) -> Self {
        Self::new(VmErrorKind::Boundary(kind))
            .with_offset(offset)
            .with_state(state)
    }

    const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    const fn with_state(mut self, state: StateId) -> Self {
        self.state = Some(state);
        self
    }

    const fn with_class(mut self, class: ClassId) -> Self {
        self.class = Some(class);
        self
    }

    fn with_actual_limit<A, L>(mut self, actual: A, limit: L) -> Self
    where
        A: TryInto<u64>,
        L: TryInto<u64>,
    {
        self.actual = actual.try_into().ok();
        self.limit = limit.try_into().ok();
        self
    }

    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for VmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{}] regex VM execution failed", self.code())?;
        if let Some(offset) = self.offset {
            write!(formatter, " offset={offset}")?;
        }
        if let Some(state) = self.state {
            write!(formatter, " state={}", state.index())?;
        }
        if let Some(class) = self.class {
            write!(formatter, " class={}", class.index())?;
        }
        if let (Some(actual), Some(limit)) = (self.actual, self.limit) {
            write!(formatter, " actual={actual} limit={limit}")?;
        }
        Ok(())
    }
}

impl std::error::Error for VmError {}

/// One deterministic, input-free cancellation observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmCancellationCheckpoint {
    pub sequence: u64,
    pub work_units: u64,
    pub offset: usize,
    pub state: Option<StateId>,
}

/// Caller-owned cancellation decision with no ambient runtime dependency.
pub trait VmCancellationProbe {
    fn should_cancel(&mut self, checkpoint: VmCancellationCheckpoint) -> bool;
}

impl<F> VmCancellationProbe for F
where
    F: FnMut(VmCancellationCheckpoint) -> bool,
{
    fn should_cancel(&mut self, checkpoint: VmCancellationCheckpoint) -> bool {
        self(checkpoint)
    }
}

/// Explicit cooperative cancellation state shared across one VM operation.
///
/// The control retains only normalized work/offset/state metadata. It never
/// stores pattern or haystack bytes, and can span nested searches so an
/// iteration has one aggregate checkpoint sequence.
pub struct VmCancellationControl<'probe> {
    check_interval_work_units: u64,
    next_check_work_units: u64,
    observed_work_units: u64,
    checkpoints: u64,
    checkpoint_fingerprint: u64,
    cancelled_at: Option<VmCancellationCheckpoint>,
    probe: &'probe mut dyn VmCancellationProbe,
}

impl<'probe> VmCancellationControl<'probe> {
    pub fn new(
        check_interval_work_units: u64,
        probe: &'probe mut dyn VmCancellationProbe,
    ) -> Result<Self, VmError> {
        if check_interval_work_units == 0 {
            return Err(VmError::new(VmErrorKind::InvalidLimits));
        }
        Ok(Self {
            check_interval_work_units,
            next_check_work_units: check_interval_work_units,
            observed_work_units: 0,
            checkpoints: 0,
            checkpoint_fingerprint: FINGERPRINT_OFFSET_BASIS,
            cancelled_at: None,
            probe,
        })
    }

    pub const fn observed_work_units(&self) -> u64 {
        self.observed_work_units
    }

    pub const fn checkpoints(&self) -> u64 {
        self.checkpoints
    }

    pub const fn checkpoint_fingerprint(&self) -> u64 {
        self.checkpoint_fingerprint
    }

    pub const fn cancelled_at(&self) -> Option<VmCancellationCheckpoint> {
        self.cancelled_at
    }

    fn observe_charge(
        &mut self,
        units: u64,
        offset: usize,
        state: Option<StateId>,
    ) -> Result<(), VmError> {
        let next = self
            .observed_work_units
            .checked_add(units)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow).with_offset(offset))?;
        while next >= self.next_check_work_units {
            self.checkpoints = checked_increment(self.checkpoints)?;
            let checkpoint = VmCancellationCheckpoint {
                sequence: self.checkpoints,
                work_units: self.next_check_work_units,
                offset,
                state,
            };
            self.checkpoint_fingerprint =
                fingerprint_mix(self.checkpoint_fingerprint, checkpoint.sequence);
            self.checkpoint_fingerprint =
                fingerprint_mix(self.checkpoint_fingerprint, checkpoint.work_units);
            self.checkpoint_fingerprint = fingerprint_mix(
                self.checkpoint_fingerprint,
                u64::try_from(checkpoint.offset)
                    .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
            );
            self.checkpoint_fingerprint = fingerprint_mix(
                self.checkpoint_fingerprint,
                match checkpoint.state {
                    Some(state) => u64::try_from(state.index())
                        .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?
                        .saturating_add(1),
                    None => 0,
                },
            );
            if self.probe.should_cancel(checkpoint) {
                self.observed_work_units = checkpoint.work_units;
                self.cancelled_at = Some(checkpoint);
                let mut error = VmError::new(VmErrorKind::Cancelled).with_offset(offset);
                error.state = state;
                error.actual = Some(checkpoint.work_units);
                return Err(error);
            }
            let Some(following) = self
                .next_check_work_units
                .checked_add(self.check_interval_work_units)
            else {
                self.next_check_work_units = u64::MAX;
                break;
            };
            self.next_check_work_units = following;
        }
        self.observed_work_units = next;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmTraceAction {
    Enqueue,
    Deduplicate,
    Visit,
    Accept,
    Epsilon,
    ConsumeMatch,
    ConsumeMiss,
    AssertionPass,
    AssertionFail,
    Clear,
    SearchStart,
    CaptureSave,
    ConsumeContinue,
    Candidate,
}

impl VmTraceAction {
    const fn tag(self) -> u64 {
        match self {
            Self::Enqueue => 1,
            Self::Deduplicate => 2,
            Self::Visit => 3,
            Self::Accept => 4,
            Self::Epsilon => 5,
            Self::ConsumeMatch => 6,
            Self::ConsumeMiss => 7,
            Self::AssertionPass => 8,
            Self::AssertionFail => 9,
            Self::Clear => 10,
            Self::SearchStart => 11,
            Self::CaptureSave => 12,
            Self::ConsumeContinue => 13,
            Self::Candidate => 14,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmTraceEvent {
    pub sequence: u64,
    pub offset: usize,
    pub state: StateId,
    pub action: VmTraceAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmResources {
    pub input_bytes: usize,
    pub offsets_examined: u64,
    pub state_visits: u64,
    pub thread_enqueues: u64,
    pub deduplicated_threads: u64,
    pub class_range_comparisons: u64,
    pub assertion_evaluations: u64,
    pub cleanup_operations: u64,
    pub peak_threads_per_offset: usize,
    pub accounted_memory_bytes: u64,
    pub work_units: u64,
}

impl VmResources {
    const fn new(input_bytes: usize, accounted_memory_bytes: u64) -> Self {
        Self {
            input_bytes,
            offsets_examined: 0,
            state_visits: 0,
            thread_enqueues: 0,
            deduplicated_threads: 0,
            class_range_comparisons: 0,
            assertion_evaluations: 0,
            cleanup_operations: 0,
            peak_threads_per_offset: 0,
            accounted_memory_bytes,
            work_units: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmOutcome {
    pub is_full_match: bool,
    pub resources: VmResources,
    pub execution_fingerprint: u64,
    pub trace: Vec<VmTraceEvent>,
    pub trace_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmMatch {
    pub span: CaptureSpan,
    /// Explicit capture groups in opening-parenthesis order.
    ///
    /// `None` means the group did not participate. An empty participating
    /// group is `Some` with equal start and end offsets.
    pub captures: Vec<Option<CaptureSpan>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureVmResources {
    pub core: VmResources,
    pub capture_saves: u64,
    pub capture_history_nodes: usize,
    pub peak_capture_history_nodes: usize,
}

impl CaptureVmResources {
    const fn new(input_bytes: usize, accounted_memory_bytes: u64) -> Self {
        Self {
            core: VmResources::new(input_bytes, accounted_memory_bytes),
            capture_saves: 0,
            capture_history_nodes: 0,
            peak_capture_history_nodes: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureVmOutcome {
    pub matched: Option<VmMatch>,
    pub resources: CaptureVmResources,
    pub execution_fingerprint: u64,
    pub trace: Vec<VmTraceEvent>,
    pub trace_truncated: bool,
}

impl CaptureVmOutcome {
    /// Return whether the one-shot search selected a match.
    pub const fn is_match(&self) -> bool {
        self.matched.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IterationPolicy {
    /// Resume at the previous non-empty match end. Empty matches advance by
    /// one complete Unicode scalar.
    NonOverlapping,
    /// Resume one complete Unicode scalar after the previous match start.
    /// This admits matches beginning inside a previous non-empty match without
    /// returning the same start twice.
    Overlapping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IterationTraceEvent {
    pub sequence: u64,
    pub search_start: usize,
    pub matched: Option<CaptureSpan>,
    pub next_search_start: Option<usize>,
    pub search_fingerprint: u64,
    pub discarded_adjacent_empty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IterationVmResources {
    pub search_attempts: u64,
    pub matches: usize,
    pub zero_width_advances: u64,
    pub overlap_advances: u64,
    pub total_work_units: u64,
    pub peak_accounted_memory_bytes: u64,
}

impl IterationVmResources {
    const fn new(accounted_memory_bytes: u64) -> Self {
        Self {
            search_attempts: 0,
            matches: 0,
            zero_width_advances: 0,
            overlap_advances: 0,
            total_work_units: 0,
            peak_accounted_memory_bytes: accounted_memory_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmIterationOutcome {
    /// Matches remain in deterministic search order and retain capture spans.
    pub matches: Vec<VmMatch>,
    pub resources: IterationVmResources,
    pub execution_fingerprint: u64,
    pub trace: Vec<IterationTraceEvent>,
    pub trace_truncated: bool,
}

impl VmIterationOutcome {
    /// Ordered, non-copying replacement targets.
    ///
    /// Capture-reference expansion belongs to R3.5; callers can pair each
    /// yielded whole-match span with the corresponding `matches` entry.
    pub fn replacement_spans(&self) -> impl ExactSizeIterator<Item = CaptureSpan> + '_ {
        self.matches.iter().map(|matched| matched.span)
    }
}

struct OffsetBucket {
    offset: Option<usize>,
    threads: Vec<StateId>,
    seen: Vec<u8>,
}

impl OffsetBucket {
    fn new(state_count: usize, thread_capacity: usize) -> Self {
        Self {
            offset: None,
            threads: Vec::with_capacity(thread_capacity),
            seen: vec![0; state_count],
        }
    }
}

struct Executor<'program, 'haystack, 'control, 'probe> {
    program: &'program Program,
    haystack: &'haystack str,
    limits: VmLimits,
    control: Option<&'control mut VmCancellationControl<'probe>>,
    buckets: Vec<OffsetBucket>,
    active_threads: usize,
    resources: VmResources,
    fingerprint: u64,
    trace: Vec<VmTraceEvent>,
    trace_truncated: bool,
    trace_sequence: u64,
}

/// Execute one validated program as an anchored, whole-haystack recognizer.
///
/// The program is validated before VM-specific allocation. Unicode classes
/// consume one scalar, byte classes consume one validated byte, and a
/// five-bucket ring bounds the maximum UTF-8 lookahead without allocating an
/// input-length-by-state matrix.
pub fn execute_full(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: VmLimits,
) -> Result<VmOutcome, VmError> {
    execute_full_with_optional_control(program, haystack, compile_limits, limits, None)
}

/// Execute whole-haystack recognition with explicit cooperative cancellation.
pub fn execute_full_with_control(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: VmLimits,
    control: &mut VmCancellationControl<'_>,
) -> Result<VmOutcome, VmError> {
    execute_full_with_optional_control(program, haystack, compile_limits, limits, Some(control))
}

fn execute_full_with_optional_control(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: VmLimits,
    control: Option<&mut VmCancellationControl<'_>>,
) -> Result<VmOutcome, VmError> {
    if !limits.invariants_hold() {
        return Err(VmError::new(VmErrorKind::InvalidLimits));
    }
    program.validate(compile_limits).map_err(VmError::compile)?;
    if haystack.len() > limits.max_input_bytes {
        return Err(VmError::new(VmErrorKind::InputLimit)
            .with_actual_limit(haystack.len(), limits.max_input_bytes));
    }

    let thread_capacity = program.states.len().min(limits.max_threads_per_offset);
    let accounted_memory_bytes = accounted_memory_bytes(
        program.states.len(),
        thread_capacity,
        limits.max_trace_events,
    )?;
    if accounted_memory_bytes > limits.max_memory_bytes {
        return Err(VmError::new(VmErrorKind::MemoryLimit)
            .with_actual_limit(accounted_memory_bytes, limits.max_memory_bytes));
    }

    Executor::new(
        program,
        haystack,
        limits,
        control,
        thread_capacity,
        accounted_memory_bytes,
    )
    .run()
}

fn accounted_memory_bytes(
    state_count: usize,
    thread_capacity: usize,
    trace_capacity: usize,
) -> Result<u64, VmError> {
    let states =
        u64::try_from(state_count).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let threads = u64::try_from(thread_capacity)
        .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let traces =
        u64::try_from(trace_capacity).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let buckets = u64::try_from(OFFSET_BUCKET_COUNT)
        .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;

    let per_bucket = threads
        .checked_mul(ACCOUNTED_THREAD_BYTES)
        .and_then(|bytes| {
            states
                .checked_mul(ACCOUNTED_SEEN_BYTE)
                .and_then(|seen| bytes.checked_add(seen))
        })
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    ACCOUNTED_VM_BASE_BYTES
        .checked_add(
            per_bucket
                .checked_mul(buckets)
                .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?,
        )
        .and_then(|bytes| {
            traces
                .checked_mul(ACCOUNTED_TRACE_EVENT_BYTES)
                .and_then(|trace_bytes| bytes.checked_add(trace_bytes))
        })
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))
}

impl<'program, 'haystack, 'control, 'probe> Executor<'program, 'haystack, 'control, 'probe> {
    fn new(
        program: &'program Program,
        haystack: &'haystack str,
        limits: VmLimits,
        control: Option<&'control mut VmCancellationControl<'probe>>,
        thread_capacity: usize,
        accounted_memory_bytes: u64,
    ) -> Self {
        Self {
            program,
            haystack,
            limits,
            control,
            buckets: (0..OFFSET_BUCKET_COUNT)
                .map(|_| OffsetBucket::new(program.states.len(), thread_capacity))
                .collect(),
            active_threads: 0,
            resources: VmResources::new(haystack.len(), accounted_memory_bytes),
            fingerprint: FINGERPRINT_OFFSET_BASIS,
            trace: Vec::with_capacity(limits.max_trace_events),
            trace_truncated: false,
            trace_sequence: 0,
        }
    }

    fn run(mut self) -> Result<VmOutcome, VmError> {
        self.enqueue(0, self.program.entry)?;
        for offset in 0..=self.haystack.len() {
            if self.active_threads == 0 {
                break;
            }
            self.charge(1, offset, None)?;
            self.resources.offsets_examined = checked_increment(self.resources.offsets_examined)?;
            let bucket_index = offset % OFFSET_BUCKET_COUNT;
            let mut cursor = 0_usize;
            while let Some(state_id) = self.buckets.get(bucket_index).and_then(|bucket| {
                if bucket.offset == Some(offset) {
                    bucket.threads.get(cursor).copied()
                } else {
                    None
                }
            }) {
                cursor = cursor
                    .checked_add(1)
                    .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
                self.charge(1, offset, Some(state_id))?;
                self.resources.state_visits = checked_increment(self.resources.state_visits)?;
                self.record(offset, state_id, VmTraceAction::Visit)?;

                let state = self.program.states.get(state_id.index()).ok_or_else(|| {
                    VmError::new(VmErrorKind::InvalidState)
                        .with_offset(offset)
                        .with_state(state_id)
                })?;
                match &state.instruction {
                    Instruction::Accept => {
                        self.record(offset, state_id, VmTraceAction::Accept)?;
                        if offset == self.haystack.len() {
                            return Ok(self.outcome(true));
                        }
                    }
                    Instruction::Jump { target } => {
                        self.record(offset, state_id, VmTraceAction::Epsilon)?;
                        self.enqueue(offset, *target)?;
                    }
                    Instruction::Split {
                        preferred,
                        fallback,
                    } => {
                        self.record(offset, state_id, VmTraceAction::Epsilon)?;
                        self.enqueue(offset, *preferred)?;
                        self.enqueue(offset, *fallback)?;
                    }
                    Instruction::Consume { class, target } => {
                        let next = self.class_next_offset(*class, offset, state_id)?;
                        if let Some(next_offset) = next {
                            self.record(offset, state_id, VmTraceAction::ConsumeMatch)?;
                            self.enqueue(next_offset, *target)?;
                        } else {
                            self.record(offset, state_id, VmTraceAction::ConsumeMiss)?;
                        }
                    }
                    Instruction::Assert { kind, target } => {
                        self.charge(1, offset, Some(state_id))?;
                        self.resources.assertion_evaluations =
                            checked_increment(self.resources.assertion_evaluations)?;
                        let passes = kind
                            .is_match(self.haystack, offset)
                            .map_err(|error| VmError::boundary(error.kind, offset, state_id))?;
                        self.record(
                            offset,
                            state_id,
                            if passes {
                                VmTraceAction::AssertionPass
                            } else {
                                VmTraceAction::AssertionFail
                            },
                        )?;
                        if passes {
                            self.enqueue(offset, *target)?;
                        }
                    }
                    Instruction::Save { target, .. } => {
                        self.record(offset, state_id, VmTraceAction::Epsilon)?;
                        self.enqueue(offset, *target)?;
                    }
                }
            }
            self.clear_bucket(offset)?;
        }
        Ok(self.outcome(false))
    }

    fn outcome(self, is_full_match: bool) -> VmOutcome {
        VmOutcome {
            is_full_match,
            resources: self.resources,
            execution_fingerprint: self.fingerprint,
            trace: self.trace,
            trace_truncated: self.trace_truncated,
        }
    }

    fn enqueue(&mut self, offset: usize, state: StateId) -> Result<(), VmError> {
        if state.index() >= self.program.states.len() {
            return Err(VmError::new(VmErrorKind::InvalidState)
                .with_offset(offset)
                .with_state(state));
        }
        let bucket_index = offset % OFFSET_BUCKET_COUNT;
        let (duplicate, thread_count) = {
            let bucket = self
                .buckets
                .get(bucket_index)
                .ok_or_else(|| VmError::new(VmErrorKind::BucketCollision))?;
            if bucket.offset.is_some_and(|assigned| assigned != offset)
                && !bucket.threads.is_empty()
            {
                return Err(VmError::new(VmErrorKind::BucketCollision)
                    .with_offset(offset)
                    .with_state(state));
            }
            (
                bucket.seen.get(state.index()).copied() == Some(1),
                bucket.threads.len(),
            )
        };

        self.charge(1, offset, Some(state))?;
        if duplicate {
            self.resources.deduplicated_threads =
                checked_increment(self.resources.deduplicated_threads)?;
            self.record(offset, state, VmTraceAction::Deduplicate)?;
            return Ok(());
        }
        if thread_count >= self.limits.max_threads_per_offset {
            return Err(VmError::new(VmErrorKind::ThreadLimit)
                .with_offset(offset)
                .with_state(state)
                .with_actual_limit(
                    thread_count.saturating_add(1),
                    self.limits.max_threads_per_offset,
                ));
        }

        let bucket = self
            .buckets
            .get_mut(bucket_index)
            .ok_or_else(|| VmError::new(VmErrorKind::BucketCollision))?;
        if bucket.offset != Some(offset) {
            bucket.offset = Some(offset);
        }
        let seen = bucket.seen.get_mut(state.index()).ok_or_else(|| {
            VmError::new(VmErrorKind::InvalidState)
                .with_offset(offset)
                .with_state(state)
        })?;
        *seen = 1;
        bucket.threads.push(state);
        self.active_threads = self
            .active_threads
            .checked_add(1)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        self.resources.thread_enqueues = checked_increment(self.resources.thread_enqueues)?;
        self.resources.peak_threads_per_offset = self
            .resources
            .peak_threads_per_offset
            .max(bucket.threads.len());
        self.record(offset, state, VmTraceAction::Enqueue)
    }

    fn clear_bucket(&mut self, offset: usize) -> Result<(), VmError> {
        let bucket_index = offset % OFFSET_BUCKET_COUNT;
        let count = self
            .buckets
            .get(bucket_index)
            .filter(|bucket| bucket.offset == Some(offset))
            .map_or(0, |bucket| bucket.threads.len());
        if count == 0 {
            return Ok(());
        }
        self.charge(
            u64::try_from(count).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
            offset,
            None,
        )?;
        let bucket = self
            .buckets
            .get_mut(bucket_index)
            .ok_or_else(|| VmError::new(VmErrorKind::BucketCollision))?;
        for state in &bucket.threads {
            let seen = bucket.seen.get_mut(state.index()).ok_or_else(|| {
                VmError::new(VmErrorKind::InvalidState)
                    .with_offset(offset)
                    .with_state(*state)
            })?;
            *seen = 0;
        }
        let trace_state = bucket.threads[0];
        bucket.threads.clear();
        bucket.offset = None;
        self.active_threads = self
            .active_threads
            .checked_sub(count)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        self.resources.cleanup_operations = self
            .resources
            .cleanup_operations
            .checked_add(
                u64::try_from(count).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
            )
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        self.record(offset, trace_state, VmTraceAction::Clear)
    }

    fn class_next_offset(
        &mut self,
        class: ClassId,
        offset: usize,
        state: StateId,
    ) -> Result<Option<usize>, VmError> {
        let ranges = &self
            .program
            .classes
            .get(class.index())
            .ok_or_else(|| {
                VmError::new(VmErrorKind::InvalidClass)
                    .with_offset(offset)
                    .with_state(state)
                    .with_class(class)
            })?
            .ranges;
        let (next_offset, comparisons) = match ranges {
            CanonicalRanges::Unicode(ranges) => {
                let Some(scalar) = self
                    .haystack
                    .get(offset..)
                    .and_then(|remaining| remaining.chars().next())
                else {
                    return Ok(None);
                };
                let (matches, comparisons) = scalar_in_ranges(ranges, scalar, offset, state)?;
                let next_offset = if matches {
                    offset
                        .checked_add(scalar.len_utf8())
                        .map(Some)
                        .ok_or_else(|| {
                            VmError::new(VmErrorKind::ArithmeticOverflow)
                                .with_offset(offset)
                                .with_state(state)
                        })?
                } else {
                    None
                };
                (next_offset, comparisons)
            }
            CanonicalRanges::Bytes(ranges) => {
                let Some(byte) = self.haystack.as_bytes().get(offset).copied() else {
                    return Ok(None);
                };
                let (matches, comparisons) = byte_in_ranges(ranges, byte, offset, state)?;
                let next_offset = if matches {
                    offset.checked_add(1).map(Some).ok_or_else(|| {
                        VmError::new(VmErrorKind::ArithmeticOverflow)
                            .with_offset(offset)
                            .with_state(state)
                    })?
                } else {
                    None
                };
                (next_offset, comparisons)
            }
        };
        self.charge(comparisons, offset, Some(state))?;
        self.resources.class_range_comparisons = self
            .resources
            .class_range_comparisons
            .checked_add(comparisons)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        Ok(next_offset)
    }

    fn charge(&mut self, units: u64, offset: usize, state: Option<StateId>) -> Result<(), VmError> {
        let next = self
            .resources
            .work_units
            .checked_add(units)
            .ok_or_else(|| {
                let mut error = VmError::new(VmErrorKind::ArithmeticOverflow).with_offset(offset);
                error.state = state;
                error
            })?;
        if next > self.limits.max_work_units {
            let mut error = VmError::new(VmErrorKind::WorkLimit)
                .with_offset(offset)
                .with_actual_limit(next, self.limits.max_work_units);
            error.state = state;
            return Err(error);
        }
        if let Some(control) = self.control.as_deref_mut() {
            control.observe_charge(units, offset, state)?;
        }
        self.resources.work_units = next;
        Ok(())
    }

    fn record(
        &mut self,
        offset: usize,
        state: StateId,
        action: VmTraceAction,
    ) -> Result<(), VmError> {
        self.trace_sequence = self
            .trace_sequence
            .checked_add(1)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        self.fingerprint = fingerprint_mix(self.fingerprint, action.tag());
        self.fingerprint = fingerprint_mix(
            self.fingerprint,
            u64::try_from(offset).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
        );
        self.fingerprint = fingerprint_mix(
            self.fingerprint,
            u64::try_from(state.index())
                .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
        );
        if self.trace.len() < self.limits.max_trace_events {
            self.trace.push(VmTraceEvent {
                sequence: self.trace_sequence,
                offset,
                state,
                action,
            });
        } else {
            self.trace_truncated = true;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureMode {
    AnchoredPrefix,
    AnchoredFull,
    Search { start_offset: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapturePc {
    State(StateId),
    /// One-byte continuation for a Unicode scalar already validated by a
    /// `Consume` state. `remaining` is in `1..=3`.
    Delay {
        target: StateId,
        remaining: u8,
    },
}

impl CapturePc {
    const fn state(self) -> StateId {
        match self {
            Self::State(state) => state,
            Self::Delay { target, .. } => target,
        }
    }

    fn seen_key(self) -> Result<usize, VmError> {
        let state = self.state();
        let base = state
            .index()
            .checked_mul(CAPTURE_SEEN_KEYS_PER_STATE)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        let suffix = match self {
            Self::State(_) => 0,
            Self::Delay { remaining, .. } => usize::from(remaining),
        };
        if suffix >= CAPTURE_SEEN_KEYS_PER_STATE {
            return Err(VmError::new(VmErrorKind::InvalidState).with_state(state));
        }
        base.checked_add(suffix)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaptureThread {
    pc: CapturePc,
    capture_head: Option<usize>,
    start: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaptureHistoryNode {
    previous: Option<usize>,
    slot: CaptureSlot,
    offset: usize,
}

struct CaptureOffsetBucket {
    offset: Option<usize>,
    threads: Vec<CaptureThread>,
}

impl CaptureOffsetBucket {
    fn new(thread_capacity: usize) -> Self {
        Self {
            offset: None,
            threads: Vec::with_capacity(thread_capacity),
        }
    }
}

struct CaptureExecutor<'program, 'haystack, 'control, 'probe> {
    program: &'program Program,
    haystack: &'haystack str,
    limits: CaptureVmLimits,
    control: Option<&'control mut VmCancellationControl<'probe>>,
    buckets: Vec<CaptureOffsetBucket>,
    active_threads: usize,
    seen: Vec<u8>,
    touched_seen: Vec<usize>,
    history: Vec<CaptureHistoryNode>,
    base_memory_bytes: u64,
    resources: CaptureVmResources,
    fingerprint: u64,
    trace: Vec<VmTraceEvent>,
    trace_truncated: bool,
    trace_sequence: u64,
}

/// Execute an anchored one-shot match and retain the prioritized capture set.
///
/// Unlike [`execute_full`], this accepts a prefix. Ordered alternation and
/// greedy/lazy repetition are selected exactly through the IR's
/// `Split(preferred, fallback)` order. The result is the first accepted path
/// after all still-live higher-priority paths have either accepted or failed.
pub fn execute_anchored(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: CaptureVmLimits,
) -> Result<CaptureVmOutcome, VmError> {
    execute_capture_mode(
        program,
        haystack,
        compile_limits,
        limits,
        CaptureMode::AnchoredPrefix,
        None,
    )
}

/// Execute an anchored one-shot match with explicit cooperative cancellation.
pub fn execute_anchored_with_control(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: CaptureVmLimits,
    control: &mut VmCancellationControl<'_>,
) -> Result<CaptureVmOutcome, VmError> {
    execute_capture_mode(
        program,
        haystack,
        compile_limits,
        limits,
        CaptureMode::AnchoredPrefix,
        Some(control),
    )
}

/// Execute an anchored whole-haystack match and retain captures.
pub fn execute_captures_full(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: CaptureVmLimits,
) -> Result<CaptureVmOutcome, VmError> {
    execute_capture_mode(
        program,
        haystack,
        compile_limits,
        limits,
        CaptureMode::AnchoredFull,
        None,
    )
}

/// Execute an anchored full capture match with explicit cancellation.
pub fn execute_captures_full_with_control(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: CaptureVmLimits,
    control: &mut VmCancellationControl<'_>,
) -> Result<CaptureVmOutcome, VmError> {
    execute_capture_mode(
        program,
        haystack,
        compile_limits,
        limits,
        CaptureMode::AnchoredFull,
        Some(control),
    )
}

/// Find one leftmost-first match and retain its prioritized capture set.
///
/// This is the one-shot primitive used by R3.4.3 iteration.
pub fn execute_search(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: CaptureVmLimits,
) -> Result<CaptureVmOutcome, VmError> {
    execute_search_from(program, haystack, compile_limits, limits, 0, None)
}

/// Find one leftmost-first match with explicit cooperative cancellation.
pub fn execute_search_with_control(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: CaptureVmLimits,
    control: &mut VmCancellationControl<'_>,
) -> Result<CaptureVmOutcome, VmError> {
    execute_search_from(program, haystack, compile_limits, limits, 0, Some(control))
}

fn execute_search_from(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: CaptureVmLimits,
    start_offset: usize,
    control: Option<&mut VmCancellationControl<'_>>,
) -> Result<CaptureVmOutcome, VmError> {
    execute_capture_mode(
        program,
        haystack,
        compile_limits,
        limits,
        CaptureMode::Search { start_offset },
        control,
    )
}

/// Repeatedly select matches under an explicit overlap policy.
///
/// The result retains captures for every match. `replacement_spans()` exposes
/// those same whole-match spans in application order without parsing or
/// expanding replacement templates.
pub fn execute_find_iter(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    policy: IterationPolicy,
    limits: IterationVmLimits,
) -> Result<VmIterationOutcome, VmError> {
    execute_find_iter_with_optional_control(program, haystack, compile_limits, policy, limits, None)
}

/// Repeatedly select matches with explicit aggregate cancellation checkpoints.
pub fn execute_find_iter_with_control(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    policy: IterationPolicy,
    limits: IterationVmLimits,
    control: &mut VmCancellationControl<'_>,
) -> Result<VmIterationOutcome, VmError> {
    execute_find_iter_with_optional_control(
        program,
        haystack,
        compile_limits,
        policy,
        limits,
        Some(control),
    )
}

fn execute_find_iter_with_optional_control(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    policy: IterationPolicy,
    limits: IterationVmLimits,
    mut control: Option<&mut VmCancellationControl<'_>>,
) -> Result<VmIterationOutcome, VmError> {
    if !limits.invariants_hold() {
        return Err(VmError::new(VmErrorKind::InvalidLimits));
    }
    program.validate(compile_limits).map_err(VmError::compile)?;
    if haystack.len() > limits.capture.vm.max_input_bytes {
        return Err(VmError::new(VmErrorKind::InputLimit)
            .with_actual_limit(haystack.len(), limits.capture.vm.max_input_bytes));
    }

    let retained_base =
        iteration_retained_memory_bytes(0, program.capture_slots, limits.max_trace_events)?;
    if retained_base > limits.capture.vm.max_memory_bytes {
        return Err(VmError::new(VmErrorKind::MemoryLimit)
            .with_actual_limit(retained_base, limits.capture.vm.max_memory_bytes));
    }

    let mut matches = Vec::new();
    let mut resources = IterationVmResources::new(retained_base);
    let mut fingerprint = FINGERPRINT_OFFSET_BASIS;
    let mut trace = Vec::with_capacity(limits.max_trace_events);
    let mut trace_truncated = false;
    let mut trace_sequence = 0_u64;
    let mut next_search_start = Some(0_usize);
    let mut last_match_end = None;

    while let Some(search_start) = next_search_start {
        iteration_charge(
            &mut resources,
            1,
            limits.capture.vm.max_work_units,
            search_start,
            control.as_deref_mut(),
        )?;
        let retained_before = iteration_retained_memory_bytes(
            matches.len(),
            program.capture_slots,
            limits.max_trace_events,
        )?;
        let remaining_memory = limits
            .capture
            .vm
            .max_memory_bytes
            .checked_sub(retained_before)
            .ok_or_else(|| {
                VmError::new(VmErrorKind::MemoryLimit)
                    .with_offset(search_start)
                    .with_actual_limit(retained_before, limits.capture.vm.max_memory_bytes)
            })?;
        if remaining_memory < ACCOUNTED_VM_BASE_BYTES {
            return Err(VmError::new(VmErrorKind::MemoryLimit)
                .with_offset(search_start)
                .with_actual_limit(retained_before, limits.capture.vm.max_memory_bytes));
        }
        let remaining_work = limits
            .capture
            .vm
            .max_work_units
            .checked_sub(resources.total_work_units)
            .ok_or_else(|| {
                VmError::new(VmErrorKind::WorkLimit)
                    .with_offset(search_start)
                    .with_actual_limit(resources.total_work_units, limits.capture.vm.max_work_units)
            })?;
        if remaining_work == 0 {
            return Err(VmError::new(VmErrorKind::WorkLimit)
                .with_offset(search_start)
                .with_actual_limit(
                    resources.total_work_units.saturating_add(1),
                    limits.capture.vm.max_work_units,
                ));
        }

        let mut search_limits = limits.capture;
        search_limits.vm.max_memory_bytes = remaining_memory;
        search_limits.vm.max_work_units = remaining_work;
        let search = execute_search_from(
            program,
            haystack,
            compile_limits,
            search_limits,
            search_start,
            control.as_deref_mut(),
        )?;
        resources.search_attempts = checked_increment(resources.search_attempts)?;
        resources.total_work_units = resources
            .total_work_units
            .checked_add(search.resources.core.work_units)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        let peak = retained_before
            .checked_add(search.resources.core.accounted_memory_bytes)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        resources.peak_accounted_memory_bytes = resources.peak_accounted_memory_bytes.max(peak);

        fingerprint = fingerprint_mix(fingerprint, search.execution_fingerprint);
        fingerprint = fingerprint_mix(
            fingerprint,
            u64::try_from(search_start)
                .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
        );

        let Some(matched) = search.matched else {
            record_iteration_trace(
                &mut trace,
                &mut trace_truncated,
                &mut trace_sequence,
                limits.max_trace_events,
                search_start,
                None,
                None,
                search.execution_fingerprint,
                false,
            )?;
            break;
        };
        let resume = next_iteration_start(haystack, matched.span, policy)?;
        if policy == IterationPolicy::NonOverlapping
            && matched.span.start == matched.span.end
            && last_match_end == Some(matched.span.end)
        {
            if resume.is_some() {
                resources.zero_width_advances = checked_increment(resources.zero_width_advances)?;
            }
            record_iteration_trace(
                &mut trace,
                &mut trace_truncated,
                &mut trace_sequence,
                limits.max_trace_events,
                search_start,
                Some(matched.span),
                resume,
                search.execution_fingerprint,
                true,
            )?;
            next_search_start = resume;
            continue;
        }
        fingerprint = mix_match_fingerprint(fingerprint, &matched)?;
        record_iteration_trace(
            &mut trace,
            &mut trace_truncated,
            &mut trace_sequence,
            limits.max_trace_events,
            search_start,
            Some(matched.span),
            resume,
            search.execution_fingerprint,
            false,
        )?;

        if matches.len() >= limits.max_matches {
            return Err(VmError::new(VmErrorKind::MatchLimit)
                .with_offset(matched.span.start)
                .with_actual_limit(matches.len().saturating_add(1), limits.max_matches));
        }
        if matched.span.start == matched.span.end && resume.is_some() {
            resources.zero_width_advances = checked_increment(resources.zero_width_advances)?;
        }
        if policy == IterationPolicy::Overlapping && resume.is_some() {
            resources.overlap_advances = checked_increment(resources.overlap_advances)?;
        }
        let matched_end = matched.span.end;
        matches.push(matched);
        resources.matches = matches.len();
        last_match_end = Some(matched_end);

        let retained_after = iteration_retained_memory_bytes(
            matches.len(),
            program.capture_slots,
            limits.max_trace_events,
        )?;
        if retained_after > limits.capture.vm.max_memory_bytes {
            return Err(VmError::new(VmErrorKind::MemoryLimit)
                .with_offset(search_start)
                .with_actual_limit(retained_after, limits.capture.vm.max_memory_bytes));
        }
        resources.peak_accounted_memory_bytes =
            resources.peak_accounted_memory_bytes.max(retained_after);
        next_search_start = resume;
    }

    Ok(VmIterationOutcome {
        matches,
        resources,
        execution_fingerprint: fingerprint,
        trace,
        trace_truncated,
    })
}

fn execute_capture_mode(
    program: &Program,
    haystack: &str,
    compile_limits: CompileLimits,
    limits: CaptureVmLimits,
    mode: CaptureMode,
    control: Option<&mut VmCancellationControl<'_>>,
) -> Result<CaptureVmOutcome, VmError> {
    if !limits.invariants_hold() {
        return Err(VmError::new(VmErrorKind::InvalidLimits));
    }
    program.validate(compile_limits).map_err(VmError::compile)?;
    if haystack.len() > limits.vm.max_input_bytes {
        return Err(VmError::new(VmErrorKind::InputLimit)
            .with_actual_limit(haystack.len(), limits.vm.max_input_bytes));
    }
    if let CaptureMode::Search { start_offset } = mode
        && (start_offset > haystack.len() || !haystack.is_char_boundary(start_offset))
    {
        return Err(VmError::new(VmErrorKind::InvalidIterationBoundary).with_offset(start_offset));
    }

    let seen_keys = program
        .states
        .len()
        .checked_mul(CAPTURE_SEEN_KEYS_PER_STATE)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let thread_capacity = seen_keys.min(limits.vm.max_threads_per_offset);
    let base_memory_bytes = capture_base_memory_bytes(
        seen_keys,
        thread_capacity,
        program.capture_slots,
        limits.vm.max_trace_events,
    )?;
    if base_memory_bytes > limits.vm.max_memory_bytes {
        return Err(VmError::new(VmErrorKind::MemoryLimit)
            .with_actual_limit(base_memory_bytes, limits.vm.max_memory_bytes));
    }

    CaptureExecutor::new(
        program,
        haystack,
        limits,
        control,
        seen_keys,
        thread_capacity,
        base_memory_bytes,
    )
    .run(mode)
}

fn capture_base_memory_bytes(
    seen_keys: usize,
    thread_capacity: usize,
    capture_slots: usize,
    trace_capacity: usize,
) -> Result<u64, VmError> {
    let seen =
        u64::try_from(seen_keys).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let threads = u64::try_from(thread_capacity)
        .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let slots =
        u64::try_from(capture_slots).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let traces =
        u64::try_from(trace_capacity).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let bucket_count = u64::try_from(CAPTURE_OFFSET_BUCKET_COUNT)
        .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;

    let bucket_threads = threads
        .checked_mul(ACCOUNTED_CAPTURE_THREAD_BYTES)
        .and_then(|bytes| bytes.checked_mul(bucket_count))
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let pending_threads = threads
        .checked_mul(ACCOUNTED_CAPTURE_THREAD_BYTES)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let touched_seen = threads
        .checked_mul(ACCOUNTED_CAPTURE_TOUCHED_KEY_BYTES)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let result_slots = slots
        .checked_mul(ACCOUNTED_CAPTURE_RESULT_SLOT_BYTES)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let trace_bytes = traces
        .checked_mul(ACCOUNTED_TRACE_EVENT_BYTES)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;

    ACCOUNTED_VM_BASE_BYTES
        .checked_add(bucket_threads)
        .and_then(|bytes| bytes.checked_add(pending_threads))
        .and_then(|bytes| bytes.checked_add(touched_seen))
        .and_then(|bytes| bytes.checked_add(seen))
        .and_then(|bytes| bytes.checked_add(result_slots))
        .and_then(|bytes| bytes.checked_add(trace_bytes))
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))
}

fn iteration_retained_memory_bytes(
    match_count: usize,
    capture_slots: usize,
    trace_capacity: usize,
) -> Result<u64, VmError> {
    let matches =
        u64::try_from(match_count).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let slots =
        u64::try_from(capture_slots).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let traces =
        u64::try_from(trace_capacity).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let captures_per_match = slots
        .checked_mul(ACCOUNTED_CAPTURE_RESULT_SLOT_BYTES)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let bytes_per_match = ACCOUNTED_ITERATION_MATCH_BYTES
        .checked_add(captures_per_match)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let match_bytes = matches
        .checked_mul(bytes_per_match)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    let trace_bytes = traces
        .checked_mul(ACCOUNTED_ITERATION_TRACE_EVENT_BYTES)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
    ACCOUNTED_VM_BASE_BYTES
        .checked_add(match_bytes)
        .and_then(|bytes| bytes.checked_add(trace_bytes))
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))
}

fn iteration_charge(
    resources: &mut IterationVmResources,
    units: u64,
    limit: u64,
    offset: usize,
    control: Option<&mut VmCancellationControl<'_>>,
) -> Result<(), VmError> {
    let next = resources
        .total_work_units
        .checked_add(units)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow).with_offset(offset))?;
    if next > limit {
        return Err(VmError::new(VmErrorKind::WorkLimit)
            .with_offset(offset)
            .with_actual_limit(next, limit));
    }
    if let Some(control) = control {
        control.observe_charge(units, offset, None)?;
    }
    resources.total_work_units = next;
    Ok(())
}

fn next_iteration_start(
    haystack: &str,
    span: CaptureSpan,
    policy: IterationPolicy,
) -> Result<Option<usize>, VmError> {
    if span.start > span.end
        || span.end > haystack.len()
        || !haystack.is_char_boundary(span.start)
        || !haystack.is_char_boundary(span.end)
    {
        return Err(VmError::new(VmErrorKind::InvalidIterationBoundary).with_offset(span.start));
    }
    match policy {
        IterationPolicy::NonOverlapping if span.start != span.end => Ok(Some(span.end)),
        IterationPolicy::NonOverlapping | IterationPolicy::Overlapping => {
            next_scalar_boundary(haystack, span.start)
        }
    }
}

fn next_scalar_boundary(haystack: &str, offset: usize) -> Result<Option<usize>, VmError> {
    if offset > haystack.len() || !haystack.is_char_boundary(offset) {
        return Err(VmError::new(VmErrorKind::InvalidIterationBoundary).with_offset(offset));
    }
    let Some(scalar) = haystack
        .get(offset..)
        .and_then(|remaining| remaining.chars().next())
    else {
        return Ok(None);
    };
    offset
        .checked_add(scalar.len_utf8())
        .map(Some)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow).with_offset(offset))
}

#[allow(clippy::too_many_arguments)]
fn record_iteration_trace(
    trace: &mut Vec<IterationTraceEvent>,
    trace_truncated: &mut bool,
    sequence: &mut u64,
    limit: usize,
    search_start: usize,
    matched: Option<CaptureSpan>,
    next_search_start: Option<usize>,
    search_fingerprint: u64,
    discarded_adjacent_empty: bool,
) -> Result<(), VmError> {
    *sequence = checked_increment(*sequence)?;
    if trace.len() < limit {
        trace.push(IterationTraceEvent {
            sequence: *sequence,
            search_start,
            matched,
            next_search_start,
            search_fingerprint,
            discarded_adjacent_empty,
        });
    } else {
        *trace_truncated = true;
    }
    Ok(())
}

fn mix_match_fingerprint(mut fingerprint: u64, matched: &VmMatch) -> Result<u64, VmError> {
    fingerprint = fingerprint_mix(
        fingerprint,
        u64::try_from(matched.span.start)
            .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
    );
    fingerprint = fingerprint_mix(
        fingerprint,
        u64::try_from(matched.span.end)
            .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
    );
    fingerprint = fingerprint_mix(
        fingerprint,
        u64::try_from(matched.captures.len())
            .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
    );
    for capture in &matched.captures {
        match capture {
            Some(span) => {
                fingerprint = fingerprint_mix(fingerprint, 1);
                fingerprint = fingerprint_mix(
                    fingerprint,
                    u64::try_from(span.start)
                        .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
                );
                fingerprint = fingerprint_mix(
                    fingerprint,
                    u64::try_from(span.end)
                        .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
                );
            }
            None => {
                fingerprint = fingerprint_mix(fingerprint, 0);
            }
        }
    }
    Ok(fingerprint)
}

impl<'program, 'haystack, 'control, 'probe> CaptureExecutor<'program, 'haystack, 'control, 'probe> {
    fn new(
        program: &'program Program,
        haystack: &'haystack str,
        limits: CaptureVmLimits,
        control: Option<&'control mut VmCancellationControl<'probe>>,
        seen_keys: usize,
        thread_capacity: usize,
        base_memory_bytes: u64,
    ) -> Self {
        Self {
            program,
            haystack,
            limits,
            control,
            buckets: (0..CAPTURE_OFFSET_BUCKET_COUNT)
                .map(|_| CaptureOffsetBucket::new(thread_capacity))
                .collect(),
            active_threads: 0,
            seen: vec![0; seen_keys],
            touched_seen: Vec::with_capacity(thread_capacity),
            history: Vec::new(),
            base_memory_bytes,
            resources: CaptureVmResources::new(haystack.len(), base_memory_bytes),
            fingerprint: FINGERPRINT_OFFSET_BASIS,
            trace: Vec::with_capacity(limits.vm.max_trace_events),
            trace_truncated: false,
            trace_sequence: 0,
        }
    }

    fn run(mut self, mode: CaptureMode) -> Result<CaptureVmOutcome, VmError> {
        let mut selected = None;
        let first_offset = match mode {
            CaptureMode::AnchoredPrefix | CaptureMode::AnchoredFull => 0,
            CaptureMode::Search { start_offset } => start_offset,
        };
        for offset in first_offset..=self.haystack.len() {
            if selected.is_some() && self.active_threads == 0 {
                break;
            }

            let mut ordered = self.take_bucket(offset)?;
            let seed = match mode {
                CaptureMode::AnchoredPrefix | CaptureMode::AnchoredFull => offset == 0,
                CaptureMode::Search { start_offset } => {
                    selected.is_none()
                        && offset >= start_offset
                        && self.haystack.is_char_boundary(offset)
                }
            };
            if seed {
                let thread = CaptureThread {
                    pc: CapturePc::State(self.program.entry),
                    capture_head: None,
                    start: offset,
                };
                self.charge(1, offset, Some(self.program.entry))?;
                self.resources.core.thread_enqueues =
                    checked_increment(self.resources.core.thread_enqueues)?;
                self.record(offset, self.program.entry, VmTraceAction::SearchStart)?;
                ordered.push(thread);
            }
            if ordered.is_empty() {
                continue;
            }
            if ordered.len() > self.limits.vm.max_threads_per_offset {
                return Err(VmError::new(VmErrorKind::ThreadLimit)
                    .with_offset(offset)
                    .with_actual_limit(ordered.len(), self.limits.vm.max_threads_per_offset));
            }

            self.charge(1, offset, None)?;
            self.resources.core.offsets_examined =
                checked_increment(self.resources.core.offsets_examined)?;
            self.resources.core.peak_threads_per_offset = self
                .resources
                .core
                .peak_threads_per_offset
                .max(ordered.len());
            let mut pending = ordered.into_iter().rev().collect::<Vec<_>>();
            let mut accepted = false;

            while let Some(thread) = pending.pop() {
                let state_id = thread.pc.state();
                let key = thread.pc.seen_key()?;
                self.charge(1, offset, Some(state_id))?;
                let seen = self.seen.get_mut(key).ok_or_else(|| {
                    VmError::new(VmErrorKind::InvalidState)
                        .with_offset(offset)
                        .with_state(state_id)
                })?;
                if *seen == 1 {
                    self.resources.core.deduplicated_threads =
                        checked_increment(self.resources.core.deduplicated_threads)?;
                    self.record(offset, state_id, VmTraceAction::Deduplicate)?;
                    continue;
                }
                *seen = 1;
                self.touched_seen.push(key);
                self.resources.core.state_visits =
                    checked_increment(self.resources.core.state_visits)?;
                self.record(offset, state_id, VmTraceAction::Visit)?;

                match thread.pc {
                    CapturePc::Delay { target, remaining } => {
                        if offset >= self.haystack.len() {
                            continue;
                        }
                        self.record(offset, target, VmTraceAction::ConsumeContinue)?;
                        let next_pc = if remaining == 1 {
                            CapturePc::State(target)
                        } else {
                            CapturePc::Delay {
                                target,
                                remaining: remaining - 1,
                            }
                        };
                        self.enqueue_next(
                            offset,
                            CaptureThread {
                                pc: next_pc,
                                ..thread
                            },
                        )?;
                    }
                    CapturePc::State(state_id) => {
                        let state = self.program.states.get(state_id.index()).ok_or_else(|| {
                            VmError::new(VmErrorKind::InvalidState)
                                .with_offset(offset)
                                .with_state(state_id)
                        })?;
                        match &state.instruction {
                            Instruction::Accept => {
                                self.record(offset, state_id, VmTraceAction::Accept)?;
                                if mode == CaptureMode::AnchoredFull
                                    && offset != self.haystack.len()
                                {
                                    continue;
                                }
                                selected = Some(self.materialize_match(thread, offset)?);
                                self.record(offset, state_id, VmTraceAction::Candidate)?;
                                pending.clear();
                                accepted = true;
                                break;
                            }
                            Instruction::Jump { target } => {
                                self.record(offset, state_id, VmTraceAction::Epsilon)?;
                                self.push_pending(
                                    &mut pending,
                                    CaptureThread {
                                        pc: CapturePc::State(*target),
                                        ..thread
                                    },
                                    offset,
                                )?;
                            }
                            Instruction::Split {
                                preferred,
                                fallback,
                            } => {
                                self.record(offset, state_id, VmTraceAction::Epsilon)?;
                                self.push_pending(
                                    &mut pending,
                                    CaptureThread {
                                        pc: CapturePc::State(*fallback),
                                        ..thread
                                    },
                                    offset,
                                )?;
                                self.push_pending(
                                    &mut pending,
                                    CaptureThread {
                                        pc: CapturePc::State(*preferred),
                                        ..thread
                                    },
                                    offset,
                                )?;
                            }
                            Instruction::Consume { class, target } => {
                                if let Some(width) =
                                    self.capture_class_width(*class, offset, state_id)?
                                {
                                    self.record(offset, state_id, VmTraceAction::ConsumeMatch)?;
                                    let pc = if width == 1 {
                                        CapturePc::State(*target)
                                    } else {
                                        let remaining = u8::try_from(width - 1).map_err(|_| {
                                            VmError::new(VmErrorKind::ArithmeticOverflow)
                                        })?;
                                        CapturePc::Delay {
                                            target: *target,
                                            remaining,
                                        }
                                    };
                                    self.enqueue_next(offset, CaptureThread { pc, ..thread })?;
                                } else {
                                    self.record(offset, state_id, VmTraceAction::ConsumeMiss)?;
                                }
                            }
                            Instruction::Assert { kind, target } => {
                                self.charge(1, offset, Some(state_id))?;
                                self.resources.core.assertion_evaluations =
                                    checked_increment(self.resources.core.assertion_evaluations)?;
                                let passes =
                                    kind.is_match(self.haystack, offset).map_err(|error| {
                                        VmError::boundary(error.kind, offset, state_id)
                                    })?;
                                self.record(
                                    offset,
                                    state_id,
                                    if passes {
                                        VmTraceAction::AssertionPass
                                    } else {
                                        VmTraceAction::AssertionFail
                                    },
                                )?;
                                if passes {
                                    self.push_pending(
                                        &mut pending,
                                        CaptureThread {
                                            pc: CapturePc::State(*target),
                                            ..thread
                                        },
                                        offset,
                                    )?;
                                }
                            }
                            Instruction::Save { slot, target } => {
                                let capture_head = self.save_capture(
                                    thread.capture_head,
                                    *slot,
                                    offset,
                                    state_id,
                                )?;
                                self.record(offset, state_id, VmTraceAction::CaptureSave)?;
                                self.push_pending(
                                    &mut pending,
                                    CaptureThread {
                                        pc: CapturePc::State(*target),
                                        capture_head: Some(capture_head),
                                        ..thread
                                    },
                                    offset,
                                )?;
                            }
                        }
                    }
                }
            }

            let cleanup = self.touched_seen.len().saturating_add(pending.len());
            self.reset_seen(offset)?;
            self.resources.core.cleanup_operations = self
                .resources
                .core
                .cleanup_operations
                .checked_add(
                    u64::try_from(cleanup)
                        .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
                )
                .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
            if accepted && self.active_threads == 0 {
                break;
            }
        }
        Ok(self.outcome(selected))
    }

    fn take_bucket(&mut self, offset: usize) -> Result<Vec<CaptureThread>, VmError> {
        let bucket_index = offset % CAPTURE_OFFSET_BUCKET_COUNT;
        let bucket = self
            .buckets
            .get_mut(bucket_index)
            .ok_or_else(|| VmError::new(VmErrorKind::BucketCollision))?;
        if bucket.offset.is_some_and(|assigned| assigned != offset) && !bucket.threads.is_empty() {
            return Err(VmError::new(VmErrorKind::BucketCollision).with_offset(offset));
        }
        if bucket.offset != Some(offset) {
            return Ok(Vec::new());
        }
        let count = bucket.threads.len();
        let ordered = bucket.threads.drain(..).collect::<Vec<_>>();
        bucket.offset = None;
        self.active_threads = self
            .active_threads
            .checked_sub(count)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        Ok(ordered)
    }

    fn push_pending(
        &mut self,
        pending: &mut Vec<CaptureThread>,
        thread: CaptureThread,
        offset: usize,
    ) -> Result<(), VmError> {
        if pending.len() >= self.limits.vm.max_threads_per_offset {
            return Err(VmError::new(VmErrorKind::ThreadLimit)
                .with_offset(offset)
                .with_state(thread.pc.state())
                .with_actual_limit(
                    pending.len().saturating_add(1),
                    self.limits.vm.max_threads_per_offset,
                ));
        }
        self.charge(1, offset, Some(thread.pc.state()))?;
        pending.push(thread);
        self.resources.core.thread_enqueues =
            checked_increment(self.resources.core.thread_enqueues)?;
        self.resources.core.peak_threads_per_offset = self
            .resources
            .core
            .peak_threads_per_offset
            .max(pending.len());
        self.record(offset, thread.pc.state(), VmTraceAction::Enqueue)
    }

    fn enqueue_next(&mut self, offset: usize, thread: CaptureThread) -> Result<(), VmError> {
        let next_offset = offset
            .checked_add(1)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        if next_offset > self.haystack.len() {
            return Ok(());
        }
        let bucket_index = next_offset % CAPTURE_OFFSET_BUCKET_COUNT;
        let thread_count = {
            let bucket = self
                .buckets
                .get(bucket_index)
                .ok_or_else(|| VmError::new(VmErrorKind::BucketCollision))?;
            if bucket
                .offset
                .is_some_and(|assigned| assigned != next_offset)
                && !bucket.threads.is_empty()
            {
                return Err(VmError::new(VmErrorKind::BucketCollision)
                    .with_offset(next_offset)
                    .with_state(thread.pc.state()));
            }
            bucket.threads.len()
        };
        if thread_count >= self.limits.vm.max_threads_per_offset {
            return Err(VmError::new(VmErrorKind::ThreadLimit)
                .with_offset(next_offset)
                .with_state(thread.pc.state())
                .with_actual_limit(
                    thread_count.saturating_add(1),
                    self.limits.vm.max_threads_per_offset,
                ));
        }

        self.charge(1, next_offset, Some(thread.pc.state()))?;
        let bucket = self
            .buckets
            .get_mut(bucket_index)
            .ok_or_else(|| VmError::new(VmErrorKind::BucketCollision))?;
        bucket.offset = Some(next_offset);
        bucket.threads.push(thread);
        self.active_threads = self
            .active_threads
            .checked_add(1)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        self.resources.core.thread_enqueues =
            checked_increment(self.resources.core.thread_enqueues)?;
        self.resources.core.peak_threads_per_offset = self
            .resources
            .core
            .peak_threads_per_offset
            .max(bucket.threads.len());
        self.record(next_offset, thread.pc.state(), VmTraceAction::Enqueue)
    }

    fn capture_class_width(
        &mut self,
        class: ClassId,
        offset: usize,
        state: StateId,
    ) -> Result<Option<usize>, VmError> {
        let ranges = &self
            .program
            .classes
            .get(class.index())
            .ok_or_else(|| {
                VmError::new(VmErrorKind::InvalidClass)
                    .with_offset(offset)
                    .with_state(state)
                    .with_class(class)
            })?
            .ranges;
        let (width, comparisons) = match ranges {
            CanonicalRanges::Unicode(ranges) => {
                let Some(scalar) = self
                    .haystack
                    .get(offset..)
                    .and_then(|remaining| remaining.chars().next())
                else {
                    return Ok(None);
                };
                let (matches, comparisons) = scalar_in_ranges(ranges, scalar, offset, state)?;
                (matches.then_some(scalar.len_utf8()), comparisons)
            }
            CanonicalRanges::Bytes(ranges) => {
                let Some(byte) = self.haystack.as_bytes().get(offset).copied() else {
                    return Ok(None);
                };
                let (matches, comparisons) = byte_in_ranges(ranges, byte, offset, state)?;
                (matches.then_some(1), comparisons)
            }
        };
        self.charge(comparisons, offset, Some(state))?;
        self.resources.core.class_range_comparisons = self
            .resources
            .core
            .class_range_comparisons
            .checked_add(comparisons)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        Ok(width)
    }

    fn save_capture(
        &mut self,
        previous: Option<usize>,
        slot: CaptureSlot,
        offset: usize,
        state: StateId,
    ) -> Result<usize, VmError> {
        let next_len = self
            .history
            .len()
            .checked_add(1)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        if next_len > self.limits.max_capture_history_nodes {
            return Err(VmError::new(VmErrorKind::CaptureHistoryLimit)
                .with_offset(offset)
                .with_state(state)
                .with_actual_limit(next_len, self.limits.max_capture_history_nodes));
        }
        let history_bytes = u64::try_from(next_len)
            .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?
            .checked_mul(ACCOUNTED_CAPTURE_HISTORY_NODE_BYTES)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?
            .max(ACCOUNTED_CAPTURE_HISTORY_ALLOCATION_FLOOR_BYTES);
        let accounted = self
            .base_memory_bytes
            .checked_add(history_bytes)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        if accounted > self.limits.vm.max_memory_bytes {
            return Err(VmError::new(VmErrorKind::MemoryLimit)
                .with_offset(offset)
                .with_state(state)
                .with_actual_limit(accounted, self.limits.vm.max_memory_bytes));
        }
        self.charge(1, offset, Some(state))?;
        let index = self.history.len();
        self.history.push(CaptureHistoryNode {
            previous,
            slot,
            offset,
        });
        self.resources.capture_saves = checked_increment(self.resources.capture_saves)?;
        self.resources.capture_history_nodes = self.history.len();
        self.resources.peak_capture_history_nodes = self
            .resources
            .peak_capture_history_nodes
            .max(self.history.len());
        self.resources.core.accounted_memory_bytes = accounted;
        Ok(index)
    }

    fn materialize_match(&mut self, thread: CaptureThread, end: usize) -> Result<VmMatch, VmError> {
        if thread.start > end
            || !self.haystack.is_char_boundary(thread.start)
            || !self.haystack.is_char_boundary(end)
        {
            return Err(VmError::new(VmErrorKind::InvalidCaptureBoundary)
                .with_offset(end)
                .with_state(thread.pc.state()));
        }
        let mut slots = vec![None; self.program.capture_slots];
        let mut cursor = thread.capture_head;
        while let Some(index) = cursor {
            self.charge(1, end, Some(thread.pc.state()))?;
            let node = self.history.get(index).copied().ok_or_else(|| {
                VmError::new(VmErrorKind::InvalidCaptureHistory)
                    .with_offset(end)
                    .with_state(thread.pc.state())
            })?;
            let slot = slots.get_mut(node.slot.index()).ok_or_else(|| {
                VmError::new(VmErrorKind::InvalidCaptureHistory)
                    .with_offset(end)
                    .with_state(thread.pc.state())
            })?;
            if slot.is_none() {
                *slot = Some(node.offset);
            }
            cursor = node.previous;
        }

        self.charge(
            u64::try_from(slots.len())
                .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
            end,
            Some(thread.pc.state()),
        )?;
        let mut captures = Vec::with_capacity(slots.len() / 2);
        for pair in slots.chunks_exact(2) {
            let capture = match (pair[0], pair[1]) {
                (None, None) => None,
                (Some(start), Some(capture_end))
                    if start <= capture_end
                        && self.haystack.is_char_boundary(start)
                        && self.haystack.is_char_boundary(capture_end) =>
                {
                    Some(CaptureSpan {
                        start,
                        end: capture_end,
                    })
                }
                (Some(_), Some(_)) => {
                    return Err(VmError::new(VmErrorKind::InvalidCaptureBoundary)
                        .with_offset(end)
                        .with_state(thread.pc.state()));
                }
                (None, Some(_)) | (Some(_), None) => {
                    return Err(VmError::new(VmErrorKind::InvalidCaptureHistory)
                        .with_offset(end)
                        .with_state(thread.pc.state()));
                }
            };
            captures.push(capture);
        }
        Ok(VmMatch {
            span: CaptureSpan {
                start: thread.start,
                end,
            },
            captures,
        })
    }

    fn reset_seen(&mut self, offset: usize) -> Result<(), VmError> {
        for key in self.touched_seen.drain(..) {
            let seen = self
                .seen
                .get_mut(key)
                .ok_or_else(|| VmError::new(VmErrorKind::InvalidState).with_offset(offset))?;
            *seen = 0;
        }
        Ok(())
    }

    fn charge(&mut self, units: u64, offset: usize, state: Option<StateId>) -> Result<(), VmError> {
        let next = self
            .resources
            .core
            .work_units
            .checked_add(units)
            .ok_or_else(|| {
                let mut error = VmError::new(VmErrorKind::ArithmeticOverflow).with_offset(offset);
                error.state = state;
                error
            })?;
        if next > self.limits.vm.max_work_units {
            let mut error = VmError::new(VmErrorKind::WorkLimit)
                .with_offset(offset)
                .with_actual_limit(next, self.limits.vm.max_work_units);
            error.state = state;
            return Err(error);
        }
        if let Some(control) = self.control.as_deref_mut() {
            control.observe_charge(units, offset, state)?;
        }
        self.resources.core.work_units = next;
        Ok(())
    }

    fn record(
        &mut self,
        offset: usize,
        state: StateId,
        action: VmTraceAction,
    ) -> Result<(), VmError> {
        self.trace_sequence = self
            .trace_sequence
            .checked_add(1)
            .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))?;
        self.fingerprint = fingerprint_mix(self.fingerprint, action.tag());
        self.fingerprint = fingerprint_mix(
            self.fingerprint,
            u64::try_from(offset).map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
        );
        self.fingerprint = fingerprint_mix(
            self.fingerprint,
            u64::try_from(state.index())
                .map_err(|_| VmError::new(VmErrorKind::ArithmeticOverflow))?,
        );
        if self.trace.len() < self.limits.vm.max_trace_events {
            self.trace.push(VmTraceEvent {
                sequence: self.trace_sequence,
                offset,
                state,
                action,
            });
        } else {
            self.trace_truncated = true;
        }
        Ok(())
    }

    fn outcome(self, matched: Option<VmMatch>) -> CaptureVmOutcome {
        CaptureVmOutcome {
            matched,
            resources: self.resources,
            execution_fingerprint: self.fingerprint,
            trace: self.trace,
            trace_truncated: self.trace_truncated,
        }
    }
}

fn checked_increment(value: u64) -> Result<u64, VmError> {
    value
        .checked_add(1)
        .ok_or_else(|| VmError::new(VmErrorKind::ArithmeticOverflow))
}

fn scalar_in_ranges(
    ranges: &[ScalarRange],
    scalar: char,
    offset: usize,
    state: StateId,
) -> Result<(bool, u64), VmError> {
    let mut low = 0_usize;
    let mut high = ranges.len();
    let mut comparisons = 0_u64;
    while low < high {
        comparisons = checked_increment(comparisons)?;
        let middle = low + (high - low) / 2;
        let range = ranges.get(middle).ok_or_else(|| {
            VmError::new(VmErrorKind::InvalidClass)
                .with_offset(offset)
                .with_state(state)
        })?;
        if scalar < range.start {
            high = middle;
        } else if scalar > range.end {
            low = middle + 1;
        } else {
            return Ok((true, comparisons));
        }
    }
    Ok((false, comparisons))
}

fn byte_in_ranges(
    ranges: &[ByteRange],
    byte: u8,
    offset: usize,
    state: StateId,
) -> Result<(bool, u64), VmError> {
    let mut low = 0_usize;
    let mut high = ranges.len();
    let mut comparisons = 0_u64;
    while low < high {
        comparisons = checked_increment(comparisons)?;
        let middle = low + (high - low) / 2;
        let range = ranges.get(middle).ok_or_else(|| {
            VmError::new(VmErrorKind::InvalidClass)
                .with_offset(offset)
                .with_state(state)
        })?;
        if byte < range.start {
            high = middle;
        } else if byte > range.end {
            low = middle + 1;
        } else {
            return Ok((true, comparisons));
        }
    }
    Ok((false, comparisons))
}

const fn fingerprint_mix(fingerprint: u64, value: u64) -> u64 {
    (fingerprint ^ value).wrapping_mul(FINGERPRINT_PRIME)
}

#[cfg(test)]
mod tests {
    use super::super::regex_boundaries::FoldBoundaryLimits;
    use super::super::regex_ir::{IR_SCHEMA_VERSION, State};
    use super::super::regex_lowering::lower;
    use super::super::regex_semantics::SemanticLimits;
    use super::super::regex_syntax::{LexerLimits, ParserLimits, SourceSpan};
    use super::*;
    use proptest::prelude::*;

    fn lower_default(pattern: &str) -> Program {
        lower(
            pattern,
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{pattern:?} must lower: {error}"))
    }

    fn execute(pattern: &str, haystack: &str) -> VmOutcome {
        execute_full(
            &lower_default(pattern),
            haystack,
            CompileLimits::default(),
            VmLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{pattern:?} on {haystack:?}: {error}"))
    }

    fn search(pattern: &str, haystack: &str) -> VmMatch {
        execute_search(
            &lower_default(pattern),
            haystack,
            CompileLimits::default(),
            CaptureVmLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{pattern:?} on {haystack:?}: {error}"))
        .matched
        .unwrap_or_else(|| panic!("{pattern:?} must match {haystack:?}"))
    }

    fn iterate(pattern: &str, haystack: &str, policy: IterationPolicy) -> VmIterationOutcome {
        execute_find_iter(
            &lower_default(pattern),
            haystack,
            CompileLimits::default(),
            policy,
            IterationVmLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{pattern:?} on {haystack:?}: {error}"))
    }

    fn span() -> SourceSpan {
        SourceSpan {
            byte_start: 0,
            byte_end: 0,
            scalar_start: 0,
            scalar_end: 0,
        }
    }

    fn compile_pattern(pattern: &str) -> PrivateCompiledPattern {
        PrivateCompiledPattern::compile(pattern, PrivateCompileLimits::default())
            .unwrap_or_else(|error| panic!("private facade rejected {pattern:?}: {error}"))
    }

    fn replace(pattern: &str, haystack: &str, template: &str) -> ReplacementOutcome {
        compile_pattern(pattern)
            .replace_all(
                haystack,
                template,
                IterationVmLimits::default(),
                ReplacementLimits::default(),
            )
            .unwrap_or_else(|error| {
                panic!("replacement {pattern:?} on {haystack:?} with {template:?}: {error}")
            })
    }

    #[test]
    fn replacement_golden_rows_cover_captures_literals_and_iteration() {
        for (pattern, haystack, template, expected) in [
            ("a", "bab", "X", "bXb"),
            ("a", "bab", "", "bb"),
            (
                "(?P<left>a)(?<right>b)?",
                "ab a",
                "<$0:$1:${2}:$left:${right}>",
                "<ab:a:b:a:b> <a:a::a:>",
            ),
            ("(a)+", "aaa", "[$1]", "[a]"),
            ("(a)?b", "b ab", "<$1>", "<> <a>"),
            ("z", "éa", "$0", "éa"),
            ("", "éa", "X", "XéXaX"),
            ("a*", "baa", "_", "_b_"),
            ("(?P<κ>a)", "a", "${κ}", "a"),
        ] {
            assert_eq!(replace(pattern, haystack, template).output, expected);
        }
    }

    #[test]
    fn compatible_replacement_templates_are_total_and_match_incumbent_edges() {
        let compiled = compile_pattern("(a)");
        let incumbent = regex::Regex::new("(a)").expect("incumbent pattern");
        for (template, expected) in [
            ("$0", "a"),
            ("${0}", "a"),
            ("$1", "a"),
            ("${1}", "a"),
            ("$missing", ""),
            ("$99", ""),
            ("$$", "$"),
            ("$$$1", "$a"),
            (r"\$1", r"\a"),
            ("$1a", ""),
            ("${1}a", "aa"),
            ("$", "$"),
            ("$!", "$!"),
            ("$é", "$é"),
            ("${name", "${name"),
            ("${}", ""),
            ("$184467440737095516160", ""),
        ] {
            let candidate = compiled
                .replace_all(
                    "a",
                    template,
                    IterationVmLimits::default(),
                    ReplacementLimits::default(),
                )
                .unwrap_or_else(|error| panic!("compatible template {template:?}: {error}"));
            let incumbent_output = incumbent.replace_all("a", template).into_owned();
            assert_eq!(candidate.output, expected, "candidate {template:?}");
            assert_eq!(candidate.output, incumbent_output, "incumbent {template:?}");
        }
    }

    #[test]
    fn strict_replacement_parser_is_explicit_typed_and_secret_safe() {
        let compiled = compile_pattern("(?P<private_capture_canary>a)");
        for (template, kind) in [
            (
                "${private_template_canary",
                ReplacementErrorKind::MalformedReference,
            ),
            (
                "$unknown_private_canary",
                ReplacementErrorKind::UnknownCapture,
            ),
            (
                "$184467440737095516160",
                ReplacementErrorKind::CaptureIndexOverflow,
            ),
        ] {
            compiled
                .parse_replacement(template, ReplacementLimits::default())
                .expect("compatibility parser remains total");
            let error = compiled
                .parse_replacement_strict(template, ReplacementLimits::default())
                .expect_err("strict parser must diagnose the reference");
            assert_eq!(error.kind, kind);
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains("private_template_canary"));
                assert!(!rendered.contains("unknown_private_canary"));
                assert!(!rendered.contains("private_capture_canary"));
            }
        }
        let compiled_debug = format!("{compiled:?}");
        assert!(compiled_debug.contains("accounted_capture_metadata_bytes"));
        assert!(!compiled_debug.contains("private_capture_canary"));
    }

    #[test]
    fn replacement_ceilings_are_exact_and_zero_use_accepts_zero() {
        let compiled = compile_pattern("(a)");
        let baseline = compiled
            .replace_all(
                "a-a",
                "<$1>",
                IterationVmLimits::default(),
                ReplacementLimits::default(),
            )
            .expect("baseline replacement");
        let exact = ReplacementLimits {
            max_template_bytes: baseline.resources.template_bytes,
            max_tokens: baseline.resources.tokens,
            max_output_bytes: baseline.resources.output_bytes,
            max_work_units: baseline.resources.work_units,
        };
        assert_eq!(
            compiled
                .replace_all("a-a", "<$1>", IterationVmLimits::default(), exact)
                .expect("exact ceilings pass"),
            baseline
        );

        for (limits, kind) in [
            (
                ReplacementLimits {
                    max_template_bytes: exact.max_template_bytes - 1,
                    ..exact
                },
                ReplacementErrorKind::TemplateLimit,
            ),
            (
                ReplacementLimits {
                    max_tokens: exact.max_tokens - 1,
                    ..exact
                },
                ReplacementErrorKind::TokenLimit,
            ),
            (
                ReplacementLimits {
                    max_output_bytes: exact.max_output_bytes - 1,
                    ..exact
                },
                ReplacementErrorKind::OutputLimit,
            ),
            (
                ReplacementLimits {
                    max_work_units: exact.max_work_units - 1,
                    ..exact
                },
                ReplacementErrorKind::WorkLimit,
            ),
        ] {
            let error = compiled
                .replace_all("a-a", "<$1>", IterationVmLimits::default(), limits)
                .expect_err("one-below ceiling fails");
            let ReplacementOperationError::Template(error) = error else {
                panic!("replacement ceiling must not become a VM error");
            };
            assert_eq!(error.kind, kind);
        }

        let zero = compile_pattern("z")
            .replace_all(
                "",
                "",
                IterationVmLimits::default(),
                ReplacementLimits {
                    max_template_bytes: 0,
                    max_tokens: 0,
                    max_output_bytes: 0,
                    max_work_units: 0,
                },
            )
            .expect("genuinely empty replacement accepts exact zero ceilings");
        assert_eq!(zero.output, "");
        assert_eq!(zero.resources.output_bytes, 0);
        assert_eq!(zero.resources.work_units, 0);
    }

    #[test]
    fn replacement_preflight_rejects_invalid_spans_before_allocating_output() {
        let compiled = compile_pattern("(a)");
        let template = compiled
            .parse_replacement("$1", ReplacementLimits::default())
            .expect("template");
        let outcome = |matches| VmIterationOutcome {
            matches,
            resources: IterationVmResources::new(0),
            execution_fingerprint: 0,
            trace: Vec::new(),
            trace_truncated: false,
        };

        for (haystack, matches, kind) in [
            (
                "aa",
                vec![
                    VmMatch {
                        span: CaptureSpan { start: 0, end: 2 },
                        captures: vec![Some(CaptureSpan { start: 0, end: 1 })],
                    },
                    VmMatch {
                        span: CaptureSpan { start: 1, end: 2 },
                        captures: vec![Some(CaptureSpan { start: 1, end: 2 })],
                    },
                ],
                ReplacementErrorKind::OverlappingMatch,
            ),
            (
                "é",
                vec![VmMatch {
                    span: CaptureSpan { start: 1, end: 2 },
                    captures: vec![None],
                }],
                ReplacementErrorKind::InvalidMatchBoundary,
            ),
            (
                "aa",
                vec![VmMatch {
                    span: CaptureSpan { start: 0, end: 1 },
                    captures: vec![Some(CaptureSpan { start: 0, end: 2 })],
                }],
                ReplacementErrorKind::InvalidMatchBoundary,
            ),
        ] {
            let error = template
                .expand(haystack, &outcome(matches), ReplacementLimits::default())
                .expect_err("invalid replacement span must fail closed");
            assert_eq!(error.kind, kind);
        }
    }

    proptest! {
        #[test]
        fn compatible_replacement_matches_regex_1_13(
            pattern in prop::sample::select(vec![
                "a", "(a)", "(a)?b", "(?P<left>a)(b)?", "", "a*", "é", "(ab|a)",
            ]),
            haystack in prop::collection::vec(
                prop::sample::select(vec!['a', 'b', 'é', '$', '_', ' ']),
                0..24,
            ).prop_map(|chars| chars.into_iter().collect::<String>()),
            template in prop::sample::select(vec![
                "", "X", "$0", "$1", "${1}", "$left", "${left}", "$missing",
                "$99", "$$", "$$$1", "$1a", "${1}a", "$", "$!", "$é",
                "${name", "${}", "$184467440737095516160", r"\$1",
            ]),
        ) {
            let incumbent = regex::Regex::new(pattern)
                .expect("incumbent accepts bounded pattern")
                .replace_all(&haystack, template)
                .into_owned();
            let candidate = compile_pattern(pattern)
                .replace_all(
                    &haystack,
                    template,
                    IterationVmLimits::default(),
                    ReplacementLimits::default(),
                )
                .expect("candidate replacement");
            prop_assert_eq!(candidate.output, incumbent);
        }
    }

    #[test]
    fn private_pattern_config_round_trips_and_loads_every_candidate_surface() {
        let pattern = "(?P<private_roundtrip_name>a)(b)?";
        let mut config = PrivatePatternConfig::new(pattern);
        config.compile_limits.lexer.max_tokens -= 1;
        config.compile_limits.parser.max_nesting -= 1;
        config.compile_limits.semantic.max_semantic_atoms -= 1;
        config.compile_limits.fold_boundary.max_fold_atoms -= 1;
        config.compile_limits.ir.max_states -= 1;
        config.iteration_limits.capture.vm.max_input_bytes -= 1;
        config.iteration_limits.max_matches -= 1;
        config.replacement_limits.max_output_bytes -= 1;
        let encoded = config.to_json().expect("serialize private pattern recipe");
        assert!(encoded.contains(pattern));
        assert_eq!(
            encoded,
            config.to_json().expect("serialization is deterministic")
        );
        assert!(
            DEFAULT_MAX_PRIVATE_PATTERN_CONFIG_BYTES
                >= config
                    .compile_limits
                    .lexer
                    .max_pattern_bytes
                    .saturating_mul(6)
                    .saturating_add(4 * 1024),
            "default document ceiling covers worst-case JSON escaping"
        );
        let encode_limit = config
            .to_json_with_document_limit(encoded.len() - 1)
            .expect_err("serializer does not emit above its document ceiling");
        assert_eq!(
            encode_limit.kind,
            PrivatePatternConfigErrorKind::DocumentLimit
        );
        assert_eq!(
            (encode_limit.actual, encode_limit.limit),
            (
                u64::try_from(encoded.len()).ok(),
                u64::try_from(encoded.len() - 1).ok()
            )
        );

        let decoded: PrivatePatternConfig =
            serde_json::from_str(&encoded).expect("decode explicit config document");
        assert_eq!(decoded, config);
        assert_eq!(
            decoded.to_json().expect("decoded recipe serializes"),
            encoded
        );
        let loaded = PrivatePatternConfig::load_json(&encoded).expect("compile-on-load recipe");
        PrivatePatternConfig::load_json_with_document_limit(&encoded, encoded.len())
            .expect("exact document ceiling passes");
        let document_limit =
            PrivatePatternConfig::load_json_with_document_limit(&encoded, encoded.len() - 1)
                .expect_err("one-below document ceiling fails before decoding");
        assert_eq!(
            document_limit.kind,
            PrivatePatternConfigErrorKind::DocumentLimit
        );
        assert_eq!(
            (document_limit.actual, document_limit.limit),
            (
                u64::try_from(encoded.len()).ok(),
                u64::try_from(encoded.len() - 1).ok()
            )
        );
        assert!(loaded.is_match("zab").expect("configured match"));
        assert_eq!(
            loaded.find("zab").expect("configured find"),
            Some(CaptureSpan { start: 1, end: 3 })
        );
        assert_eq!(
            loaded
                .captures("zab")
                .expect("configured captures")
                .expect("selected match")
                .captures,
            vec![
                Some(CaptureSpan { start: 1, end: 2 }),
                Some(CaptureSpan { start: 2, end: 3 }),
            ]
        );
        assert_eq!(
            loaded
                .find_iter("ab a", IterationPolicy::NonOverlapping)
                .expect("configured iteration")
                .matches
                .len(),
            2
        );
        assert_eq!(
            loaded
                .replace_all("ab a", "<$private_roundtrip_name>")
                .expect("configured replacement")
                .output,
            "<a> <a>"
        );

        let config_debug = format!("{config:?}");
        assert!(config_debug.contains("pattern_bytes"));
        let loaded_debug = format!("{loaded:?}");
        for rendered in [config_debug, loaded_debug] {
            assert!(!rendered.contains(pattern));
            assert!(!rendered.contains("private_roundtrip_name"));
        }
    }

    #[test]
    fn private_pattern_config_rejects_invalid_documents_atomically_and_secret_safely() {
        let malformed_document =
            r#"{"schema_version":1,"pattern":"private_json_canary","compile_limits":}"#;
        let malformed = PrivatePatternConfig::load_json(malformed_document)
            .expect_err("malformed JSON must not yield a partial recipe");
        assert_eq!(malformed.kind, PrivatePatternConfigErrorKind::Decode);

        let mut unknown_value =
            serde_json::to_value(PrivatePatternConfig::new("a")).expect("serialize config value");
        unknown_value
            .as_object_mut()
            .expect("config object")
            .insert("private_unknown_canary".to_owned(), serde_json::json!(true));
        let unknown_document = serde_json::to_string(&unknown_value).expect("unknown field JSON");
        let unknown = PrivatePatternConfig::load_json(&unknown_document)
            .expect_err("unknown fields must fail closed");
        assert_eq!(unknown.kind, PrivatePatternConfigErrorKind::Decode);

        let mut nested_unknown_value =
            serde_json::to_value(PrivatePatternConfig::new("a")).expect("serialize config value");
        nested_unknown_value["iteration_limits"]["capture"]["vm"]
            .as_object_mut()
            .expect("nested VM limit object")
            .insert(
                "private_nested_unknown_canary".to_owned(),
                serde_json::json!(true),
            );
        let nested_unknown_document =
            serde_json::to_string(&nested_unknown_value).expect("nested unknown field JSON");
        let nested_unknown = PrivatePatternConfig::load_json(&nested_unknown_document)
            .expect_err("nested unknown fields must fail closed");
        assert_eq!(nested_unknown.kind, PrivatePatternConfigErrorKind::Decode);

        let mut missing_value =
            serde_json::to_value(PrivatePatternConfig::new("private_missing_canary"))
                .expect("serialize config value");
        missing_value
            .as_object_mut()
            .expect("config object")
            .remove("compile_limits");
        let missing_document = serde_json::to_string(&missing_value).expect("missing field JSON");
        let missing = PrivatePatternConfig::load_json(&missing_document)
            .expect_err("missing fields must fail closed");
        assert_eq!(missing.kind, PrivatePatternConfigErrorKind::Decode);

        let mut unsupported = PrivatePatternConfig::new("a");
        unsupported.schema_version = PRIVATE_PATTERN_CONFIG_SCHEMA_VERSION + 1;
        let unsupported = PrivatePatternConfig::load(unsupported)
            .expect_err("unsupported schema must not compile");
        assert_eq!(
            unsupported.kind,
            PrivatePatternConfigErrorKind::UnsupportedSchema
        );

        let mut invalid_limits = PrivatePatternConfig::new("a");
        invalid_limits.iteration_limits.max_matches = 0;
        let invalid_limits = PrivatePatternConfig::load(invalid_limits)
            .expect_err("invalid execution limits must not compile");
        assert_eq!(
            invalid_limits.kind,
            PrivatePatternConfigErrorKind::InvalidIterationLimits
        );
        assert_eq!(invalid_limits.field, Some("iteration.max_matches"));
        assert_eq!(
            (invalid_limits.actual, invalid_limits.limit),
            (Some(0), Some(1))
        );

        let invalid_pattern = "private_compile_canary\\";
        let compile = PrivatePatternConfig::load(PrivatePatternConfig::new(invalid_pattern))
            .expect_err("invalid pattern must not yield a partial compiled value");
        assert_eq!(compile.kind, PrivatePatternConfigErrorKind::Compile);

        let prior = PrivatePatternConfig::load(PrivatePatternConfig::new("a+"))
            .expect("load prior pattern");
        let _ = PrivatePatternConfig::load(PrivatePatternConfig::new("("))
            .expect_err("later invalid load fails");
        assert!(prior.is_match("zaaa").expect("prior load remains reusable"));

        let mut zero_replacement = PrivatePatternConfig::new("z");
        zero_replacement.replacement_limits = ReplacementLimits {
            max_template_bytes: 0,
            max_tokens: 0,
            max_output_bytes: 0,
            max_work_units: 0,
        };
        let zero_replacement = PrivatePatternConfig::load(zero_replacement)
            .expect("zero replacement ceilings are valid when the operation uses zero");
        assert_eq!(
            zero_replacement
                .replace_all("", "")
                .expect("zero-use replacement")
                .output,
            ""
        );

        for (error, canary) in [
            (malformed, "private_json_canary"),
            (unknown, "private_unknown_canary"),
            (nested_unknown, "private_nested_unknown_canary"),
            (missing, "private_missing_canary"),
            (compile, "private_compile_canary"),
        ] {
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains(canary));
            }
        }
    }

    #[test]
    fn loaded_private_pattern_is_reusable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LoadedPrivatePattern>();

        let loaded = std::sync::Arc::new(
            PrivatePatternConfig::load(PrivatePatternConfig::new("(?P<value>a+)"))
                .expect("load shared pattern"),
        );
        let start = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        std::thread::scope(|scope| {
            let mut joins = Vec::new();
            for _ in 0..8 {
                let loaded = std::sync::Arc::clone(&loaded);
                let worker_start = std::sync::Arc::clone(&start);
                let worker = std::thread::Builder::new().spawn_scoped(scope, move || {
                    let (lock, ready) = &*worker_start;
                    let started = lock.lock().expect("shared start gate");
                    drop(
                        ready
                            .wait_while(started, |started| !*started)
                            .expect("shared start gate wait"),
                    );
                    for _ in 0..32 {
                        assert!(loaded.is_match("zaaa").expect("shared match"));
                        assert_eq!(
                            loaded
                                .replace_all("zaaa", "<$value>")
                                .expect("shared replacement")
                                .output,
                            "z<aaa>"
                        );
                    }
                });
                match worker {
                    Ok(join) => joins.push(join),
                    Err(error) => {
                        let (lock, ready) = &*start;
                        *lock.lock().expect("release start gate after spawn failure") = true;
                        ready.notify_all();
                        panic!("failed to spawn shared config worker: {error}");
                    }
                }
            }
            let (lock, ready) = &*start;
            *lock.lock().expect("release shared start gate") = true;
            ready.notify_all();
            for join in joins {
                join.join().expect("shared config worker");
            }
        });
    }

    fn private_cache(limits: PrivatePatternCacheLimits) -> PrivatePatternCache {
        PrivatePatternCache::new(limits).expect("valid private cache limits")
    }

    #[test]
    fn private_pattern_cache_limits_and_failures_are_atomic_and_secret_safe() {
        let invalid = PrivatePatternCache::new(PrivatePatternCacheLimits {
            max_entries: 0,
            ..PrivatePatternCacheLimits::default()
        })
        .expect_err("zero entry limit is invalid");
        assert_eq!(invalid.kind, PrivatePatternCacheErrorKind::InvalidLimits);

        let pattern_limited = private_cache(PrivatePatternCacheLimits {
            max_pattern_bytes: 1,
            ..PrivatePatternCacheLimits::default()
        });
        let private_pattern = "private-cache-pattern-canary";
        let limited = pattern_limited
            .get_or_compile(PrivatePatternConfig::new(private_pattern))
            .expect_err("pattern ceiling fails before compile");
        assert_eq!(limited.kind, PrivatePatternCacheErrorKind::PatternLimit);
        assert_eq!(pattern_limited.snapshot().entries, 0);

        let byte_limited = private_cache(PrivatePatternCacheLimits {
            max_live_accounted_bytes: ACCOUNTED_PRIVATE_PATTERN_RESIDENT_OVERHEAD_BYTES,
            ..PrivatePatternCacheLimits::default()
        });
        let oversized = byte_limited
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect_err("compiled resident cannot exceed the live-byte ceiling");
        assert_eq!(oversized.kind, PrivatePatternCacheErrorKind::EntryTooLarge);
        assert_eq!(byte_limited.snapshot().entries, 0);
        assert_eq!(byte_limited.snapshot().live_accounted_bytes, 0);
        assert_eq!(byte_limited.snapshot().inflight_compiles, 0);
        assert_eq!(byte_limited.snapshot().inflight_compile_accounted_bytes, 0);

        let cache = private_cache(PrivatePatternCacheLimits::default());
        let malformed_pattern = "private-cache-malformed-canary\\";
        let malformed = cache
            .get_or_compile(PrivatePatternConfig::new(malformed_pattern))
            .expect_err("malformed pattern is never negative-cached");
        assert_eq!(malformed.kind, PrivatePatternCacheErrorKind::Config);
        assert_eq!(
            malformed.config_error.map(|error| error.kind),
            Some(PrivatePatternConfigErrorKind::Compile)
        );
        assert_eq!(cache.snapshot().entries, 0);
        assert_eq!(cache.snapshot().inflight_compiles, 0);
        assert_eq!(cache.snapshot().inflight_compile_accounted_bytes, 0);
        let debug_pattern = "(?P<private_cache_debug_canary>a)";
        let debug_lease = cache
            .get_or_compile(PrivatePatternConfig::new(debug_pattern))
            .expect("admit debug canary pattern");
        for rendered in [
            limited.to_string(),
            format!("{limited:?}"),
            malformed.to_string(),
            format!("{malformed:?}"),
            format!("{cache:?}"),
            format!("{debug_lease:?}"),
        ] {
            assert!(!rendered.contains(private_pattern));
            assert!(!rendered.contains("private-cache-malformed-canary"));
            assert!(!rendered.contains("private_cache_debug_canary"));
        }
        cache.shutdown();
        drop(debug_lease);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_lru_eviction_tracks_evicted_leases_until_drop() {
        let cache = private_cache(PrivatePatternCacheLimits {
            max_entries: 2,
            ..PrivatePatternCacheLimits::default()
        });
        let first = cache
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect("admit first pattern");
        let second = cache
            .get_or_compile(PrivatePatternConfig::new("b"))
            .expect("admit second pattern");
        let second_bytes = second.accounted_live_bytes();
        let second_weak = Arc::downgrade(&second.resident);

        let first_hit = cache
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect("refresh first as most recently used");
        drop(first_hit);
        let third = cache
            .get_or_compile(PrivatePatternConfig::new("c"))
            .expect("third pattern evicts least-recently-used second entry");
        let after_eviction = cache.snapshot();
        assert_eq!(after_eviction.entries, 2);
        assert_eq!(after_eviction.hits, 1);
        assert_eq!(after_eviction.evictions, 1);
        assert!(second_weak.upgrade().is_some());
        assert!(second.is_match("b").expect("evicted lease remains usable"));

        let live_before_second_drop = after_eviction.live_accounted_bytes;
        drop(second);
        assert!(second_weak.upgrade().is_none());
        assert_eq!(
            cache.snapshot().live_accounted_bytes,
            live_before_second_drop - second_bytes
        );

        cache.clear();
        let after_clear = cache.snapshot();
        assert_eq!(after_clear.entries, 0);
        assert!(after_clear.live_accounted_bytes > 0);
        assert!(
            first
                .is_match("a")
                .expect("cleared first lease remains usable")
        );
        assert!(
            third
                .is_match("c")
                .expect("cleared third lease remains usable")
        );
        drop(first);
        drop(third);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_pinned_capacity_refusal_preserves_existing_entry() {
        let sizing_cache = private_cache(PrivatePatternCacheLimits::default());
        let sizing = sizing_cache
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect("measure deterministic resident charge");
        let one_resident = sizing.accounted_live_bytes();
        sizing_cache.shutdown();
        drop(sizing);
        assert_eq!(sizing_cache.snapshot().live_accounted_bytes, 0);

        let cache = private_cache(PrivatePatternCacheLimits {
            max_entries: 2,
            max_live_accounted_bytes: one_resident,
            ..PrivatePatternCacheLimits::default()
        });
        let admitted = cache
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect("admit one resident");
        let mut distinct_config = PrivatePatternConfig::new("a");
        distinct_config.iteration_limits.max_matches -= 1;
        let refused = cache
            .get_or_compile(distinct_config)
            .expect_err("active lease pins the complete live-byte budget");
        assert_eq!(refused.kind, PrivatePatternCacheErrorKind::CapacityPinned);
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 1);
        assert_eq!(snapshot.live_accounted_bytes, one_resident);
        assert_eq!(snapshot.evictions, 0, "failed admission is non-destructive");
        assert!(
            admitted
                .is_match("za")
                .expect("existing resident survives refusal")
        );
        cache.shutdown();
        assert_eq!(cache.snapshot().entries, 0);
        assert_eq!(cache.snapshot().live_accounted_bytes, one_resident);
        drop(admitted);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_duplicate_compile_race_admits_one_exact_winner() {
        let cache = Arc::new(private_cache(PrivatePatternCacheLimits {
            max_inflight_compiles: 2,
            max_inflight_compile_accounted_bytes: 3 * 1024 * 1024 * 1024,
            ..PrivatePatternCacheLimits::default()
        }));
        let before_admission = Arc::new(std::sync::Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let before_admission = Arc::clone(&before_admission);
                std::thread::spawn(move || {
                    let mut probe = |checkpoint| {
                        if checkpoint == PrivatePatternCacheCheckpoint::Admission {
                            before_admission.wait();
                        }
                        false
                    };
                    let mut control = PrivatePatternCacheAdmissionControl::new(&mut probe);
                    let lease = cache
                        .get_or_compile_with_admission_control(
                            PrivatePatternConfig::new("(?P<value>a+)"),
                            &mut control,
                        )
                        .expect("racing compile returns admitted winner");
                    assert!(lease.is_match("zaaa").expect("winner is usable"));
                })
            })
            .collect::<Vec<_>>();
        before_admission.wait();
        for handle in handles {
            handle.join().expect("duplicate compile worker joins");
        }

        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 1);
        assert_eq!(snapshot.misses, 2);
        assert_eq!(snapshot.compilations, 2);
        assert_eq!(snapshot.admissions, 1);
        assert_eq!(snapshot.duplicate_compiles, 1);
        assert_eq!(snapshot.inflight_compiles, 0);
        assert_eq!(snapshot.inflight_compile_accounted_bytes, 0);
        cache.shutdown();
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_inflight_compile_ceiling_fails_closed() {
        let default_reservation =
            private_pattern_compile_reservation_bytes(&PrivatePatternConfig::new("a"))
                .expect("default compile reservation is representable");
        assert_eq!(DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILES, 1);
        assert!(
            default_reservation
                <= DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILE_ACCOUNTED_BYTES
        );
        assert!(
            default_reservation.saturating_mul(2)
                > DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILE_ACCOUNTED_BYTES,
            "the default count must not advertise concurrency rejected by the byte ceiling"
        );

        let cache = Arc::new(private_cache(PrivatePatternCacheLimits {
            max_inflight_compiles: 1,
            ..PrivatePatternCacheLimits::default()
        }));
        let (compiled_tx, compiled_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let worker_cache = Arc::clone(&cache);
        let worker = std::thread::spawn(move || {
            let mut probe = |checkpoint| {
                if checkpoint == PrivatePatternCacheCheckpoint::Admission {
                    compiled_tx
                        .send(())
                        .expect("announce occupied compile slot");
                    release_rx.recv().expect("release occupied compile slot");
                }
                false
            };
            let mut control = PrivatePatternCacheAdmissionControl::new(&mut probe);
            worker_cache.get_or_compile_with_admission_control(
                PrivatePatternConfig::new("a+"),
                &mut control,
            )
        });

        compiled_rx.recv().expect("first compile occupies slot");
        assert_eq!(cache.snapshot().inflight_compiles, 1);
        let refused = cache
            .get_or_compile(PrivatePatternConfig::new("b+"))
            .expect_err("second concurrent compile exceeds explicit ceiling");
        assert_eq!(refused.kind, PrivatePatternCacheErrorKind::CompileCapacity);
        assert_eq!(cache.snapshot().entries, 0);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);

        release_tx.send(()).expect("release first compile");
        let admitted = worker
            .join()
            .expect("compile-capacity worker joins")
            .expect("first compile admits");
        assert!(admitted.is_match("aaa").expect("first resident is usable"));
        assert_eq!(cache.snapshot().inflight_compiles, 0);
        assert_eq!(cache.snapshot().inflight_compile_accounted_bytes, 0);
        cache.shutdown();
        drop(admitted);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_inflight_compile_byte_ceiling_releases_exactly() {
        let config = PrivatePatternConfig::new("a+");
        let reservation = private_pattern_compile_reservation_bytes(&config)
            .expect("default compile reservation is representable");
        let cache = Arc::new(private_cache(PrivatePatternCacheLimits {
            max_inflight_compiles: 2,
            max_inflight_compile_accounted_bytes: reservation,
            ..PrivatePatternCacheLimits::default()
        }));
        let (compiled_tx, compiled_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let worker_cache = Arc::clone(&cache);
        let worker = std::thread::spawn(move || {
            let mut probe = |checkpoint| {
                if checkpoint == PrivatePatternCacheCheckpoint::Admission {
                    compiled_tx
                        .send(())
                        .expect("announce occupied compile-byte budget");
                    release_rx
                        .recv()
                        .expect("release occupied compile-byte budget");
                }
                false
            };
            let mut control = PrivatePatternCacheAdmissionControl::new(&mut probe);
            worker_cache.get_or_compile_with_admission_control(config, &mut control)
        });

        compiled_rx
            .recv()
            .expect("first compile occupies byte reservation");
        let occupied = cache.snapshot();
        assert_eq!(occupied.inflight_compiles, 1);
        assert_eq!(occupied.inflight_compile_accounted_bytes, reservation);
        let refused = cache
            .get_or_compile(PrivatePatternConfig::new("b+"))
            .expect_err("second compile exceeds aggregate byte reservation");
        assert_eq!(
            refused.kind,
            PrivatePatternCacheErrorKind::CompileMemoryCapacity
        );
        assert_eq!(cache.snapshot().inflight_compiles, 1);
        assert_eq!(
            cache.snapshot().inflight_compile_accounted_bytes,
            reservation
        );

        release_tx.send(()).expect("release first byte reservation");
        let admitted = worker
            .join()
            .expect("compile-byte worker joins")
            .expect("first compile admits");
        let released = cache.snapshot();
        assert_eq!(released.inflight_compiles, 0);
        assert_eq!(released.inflight_compile_accounted_bytes, 0);
        cache.shutdown();
        drop(admitted);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_lookup_work_and_closed_precedence_fail_closed() {
        let pattern = "a".repeat(1024);
        let exact_hit_work = u64::try_from(pattern.len() * 3).expect("bounded lookup work")
            + ACCOUNTED_PRIVATE_PATTERN_LOOKUP_ENTRY_WORK_UNITS;
        let cache = private_cache(PrivatePatternCacheLimits {
            max_lookup_work_units: exact_hit_work - 1,
            ..PrivatePatternCacheLimits::default()
        });
        let lease = cache
            .get_or_compile(PrivatePatternConfig::new(pattern.clone()))
            .expect("first bounded lookup and admission");
        let work_limited = cache
            .get_or_compile(PrivatePatternConfig::new(pattern))
            .expect_err("exact collision-safe verification obeys lookup ceiling");
        assert_eq!(
            work_limited.kind,
            PrivatePatternCacheErrorKind::LookupWorkLimit
        );
        assert_eq!(cache.snapshot().hits, 0);
        assert_eq!(cache.snapshot().entries, 1);

        cache.shutdown();
        let closed = cache
            .get_or_compile(PrivatePatternConfig::new("z".repeat(2 * 1024 * 1024)))
            .expect_err("closed refusal precedes pattern-length diagnostics");
        assert_eq!(closed.kind, PrivatePatternCacheErrorKind::Closed);
        assert_eq!((closed.actual, closed.limit), (None, None));
        drop(lease);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_cancellation_callbacks_are_outside_lock_and_never_admit() {
        let cache = private_cache(PrivatePatternCacheLimits::default());
        let mut precompile_probe = |checkpoint| {
            let snapshot = cache.snapshot();
            assert_eq!(snapshot.entries, 0, "callback can re-enter cache snapshot");
            checkpoint == PrivatePatternCacheCheckpoint::Compile
        };
        let mut precompile_control =
            PrivatePatternCacheAdmissionControl::new(&mut precompile_probe);
        let precompile = cache
            .get_or_compile_with_admission_control(
                PrivatePatternConfig::new("a"),
                &mut precompile_control,
            )
            .expect_err("precompile cancellation refuses work");
        assert_eq!(precompile.kind, PrivatePatternCacheErrorKind::Cancelled);
        assert_eq!(
            precompile_control.cancelled_at(),
            Some(PrivatePatternCacheCheckpoint::Compile)
        );
        assert_eq!(cache.snapshot().compilations, 0);

        let mut preadmission_probe = |checkpoint| {
            let snapshot = cache.snapshot();
            assert_eq!(snapshot.entries, 0, "post-compile callback holds no lock");
            checkpoint == PrivatePatternCacheCheckpoint::Admission
        };
        let mut preadmission_control =
            PrivatePatternCacheAdmissionControl::new(&mut preadmission_probe);
        let preadmission = cache
            .get_or_compile_with_admission_control(
                PrivatePatternConfig::new("a"),
                &mut preadmission_control,
            )
            .expect_err("post-compile cancellation discards result");
        assert_eq!(preadmission.kind, PrivatePatternCacheErrorKind::Cancelled);
        assert_eq!(
            preadmission_control.cancelled_at(),
            Some(PrivatePatternCacheCheckpoint::Admission)
        );
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 0);
        assert_eq!(snapshot.live_accounted_bytes, 0);
        assert_eq!(snapshot.compilations, 1);
        assert_eq!(snapshot.inflight_compiles, 0);
        assert_eq!(snapshot.inflight_compile_accounted_bytes, 0);

        let admitted = cache
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect("admit cache-hit cancellation fixture");
        let mut hit_probe = |checkpoint| checkpoint == PrivatePatternCacheCheckpoint::Lookup;
        let mut hit_control = PrivatePatternCacheAdmissionControl::new(&mut hit_probe);
        let hit_cancelled = cache
            .get_or_compile_with_admission_control(PrivatePatternConfig::new("a"), &mut hit_control)
            .expect_err("lookup cancellation takes precedence over cache hit");
        assert_eq!(hit_cancelled.kind, PrivatePatternCacheErrorKind::Cancelled);
        assert_eq!(
            hit_control.cancelled_at(),
            Some(PrivatePatternCacheCheckpoint::Lookup)
        );
        assert_eq!(cache.snapshot().hits, 0);
        cache.shutdown();
        drop(admitted);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_shutdown_wins_inflight_admission_and_is_idempotent() {
        let cache = Arc::new(private_cache(PrivatePatternCacheLimits::default()));
        let (compiled_tx, compiled_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let worker_cache = Arc::clone(&cache);
        let worker = std::thread::spawn(move || {
            let mut probe = |checkpoint| {
                if checkpoint == PrivatePatternCacheCheckpoint::Admission {
                    compiled_tx.send(()).expect("announce compiled result");
                    release_rx.recv().expect("release admission probe");
                }
                false
            };
            let mut control = PrivatePatternCacheAdmissionControl::new(&mut probe);
            worker_cache.get_or_compile_with_admission_control(
                PrivatePatternConfig::new("a+"),
                &mut control,
            )
        });

        compiled_rx
            .recv()
            .expect("worker reached pre-admission state");
        cache.shutdown();
        cache.shutdown();
        release_tx.send(()).expect("release worker");
        let refused = worker
            .join()
            .expect("in-flight compile worker joins")
            .expect_err("closed cache refuses the compiled result");
        assert_eq!(refused.kind, PrivatePatternCacheErrorKind::Closed);
        let snapshot = cache.snapshot();
        assert!(snapshot.closed);
        assert_eq!(snapshot.entries, 0);
        assert_eq!(snapshot.live_accounted_bytes, 0);
        assert_eq!(snapshot.inflight_compiles, 0);
        assert_eq!(snapshot.inflight_compile_accounted_bytes, 0);
        let later = cache
            .get_or_compile(PrivatePatternConfig::new("b"))
            .expect_err("closed cache refuses later lookup");
        assert_eq!(later.kind, PrivatePatternCacheErrorKind::Closed);
    }

    #[test]
    fn private_pattern_cache_eviction_races_controlled_use_without_leak() {
        let cache = Arc::new(private_cache(PrivatePatternCacheLimits {
            max_entries: 1,
            ..PrivatePatternCacheLimits::default()
        }));
        let lease = cache
            .get_or_compile(PrivatePatternConfig::new("(a+)"))
            .expect("admit controlled-use pattern");
        let weak = Arc::downgrade(&lease.resident);
        let worker_lease = lease.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let (go_tx, go_rx) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            ready_tx.send(()).expect("announce held lease");
            go_rx.recv().expect("begin controlled use");
            let mut probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == 3;
            let mut control = VmCancellationControl::new(3, &mut probe).expect("valid control");
            let private_haystack = "r3_6_probe-aaaa";
            assert_eq!(
                private_haystack.find('a'),
                Some(private_haystack.len() - 4),
                "controlled-use premise has no earlier match"
            );
            let error = worker_lease
                .find_iter_with_control(
                    private_haystack,
                    IterationPolicy::NonOverlapping,
                    &mut control,
                )
                .expect_err("controlled use cancels after eviction");
            assert_eq!(error.kind, VmErrorKind::Cancelled);
        });

        ready_rx.recv().expect("worker holds resident lease");
        let replacement = cache
            .get_or_compile(PrivatePatternConfig::new("b"))
            .expect("evict held resident while preserving its lease");
        assert_eq!(cache.snapshot().entries, 1);
        assert!(weak.upgrade().is_some());
        go_tx.send(()).expect("release controlled use");
        worker.join().expect("controlled-use worker joins");
        assert!(
            lease
                .is_match("zaaa")
                .expect("evicted original remains usable")
        );

        cache.shutdown();
        drop(replacement);
        drop(lease);
        assert!(weak.upgrade().is_none());
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_compiled_pattern_compiles_once_without_retaining_source_text() {
        let pattern = "(?P<r3_5_private_compiled_pattern_canary>a)?b";
        let compiled = compile_pattern(pattern);
        let rendered = format!("{compiled:?}");
        assert!(rendered.contains("PrivateCompiledPattern"));
        assert!(rendered.contains("capture_slots"));
        assert!(!rendered.contains(pattern));
        assert!(!rendered.contains("r3_5_private_compiled_pattern_canary"));

        let malformed = "r3_5_private_compiled_error_canary\\";
        let error = PrivateCompiledPattern::compile(malformed, PrivateCompileLimits::default())
            .expect_err("trailing escape must fail during private compilation");
        assert_eq!(error.code(), "RGX-LEX-E003");
        for diagnostic in [error.to_string(), format!("{error:?}")] {
            assert!(!diagnostic.contains(malformed));
            assert!(!diagnostic.contains("r3_5_private_compiled_error_canary"));
        }
    }

    #[test]
    fn private_compiled_pattern_match_find_captures_and_reuse_are_exact() {
        let priority = compile_pattern("(a|ab)");
        assert!(
            priority
                .is_match("zab", CaptureVmLimits::default())
                .expect("match query")
        );
        assert!(
            !priority
                .is_match("zzz", CaptureVmLimits::default())
                .expect("no-match query")
        );
        assert_eq!(
            priority
                .find("zab", CaptureVmLimits::default())
                .expect("leftmost find"),
            Some(CaptureSpan { start: 1, end: 2 })
        );
        for _ in 0..16 {
            let selected = priority
                .captures("zab", CaptureVmLimits::default())
                .expect("reused capture query")
                .expect("priority pattern matches");
            assert_eq!(selected.span, CaptureSpan { start: 1, end: 2 });
            assert_eq!(
                selected.captures,
                vec![Some(CaptureSpan { start: 1, end: 2 })]
            );
        }

        let participation = compile_pattern("(a)?b");
        let absent = participation
            .captures("b", CaptureVmLimits::default())
            .expect("optional capture query")
            .expect("whole expression matches");
        assert_eq!(absent.span, CaptureSpan { start: 0, end: 1 });
        assert_eq!(absent.captures, vec![None]);

        let empty = compile_pattern("");
        assert_eq!(
            empty
                .find("é", CaptureVmLimits::default())
                .expect("zero-width find"),
            Some(CaptureSpan { start: 0, end: 0 })
        );
    }

    #[test]
    fn private_compiled_pattern_iteration_is_stable_and_unicode_safe() {
        let overlapping = compile_pattern("aba");
        let non_overlapping = overlapping
            .find_iter(
                "ababa",
                IterationPolicy::NonOverlapping,
                IterationVmLimits::default(),
            )
            .expect("non-overlapping iteration");
        assert_eq!(
            non_overlapping.replacement_spans().collect::<Vec<_>>(),
            vec![CaptureSpan { start: 0, end: 3 }]
        );
        let first = overlapping
            .find_iter(
                "ababa",
                IterationPolicy::Overlapping,
                IterationVmLimits::default(),
            )
            .expect("overlapping iteration");
        let second = overlapping
            .find_iter(
                "ababa",
                IterationPolicy::Overlapping,
                IterationVmLimits::default(),
            )
            .expect("replayed overlapping iteration");
        assert_eq!(
            first.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 3 },
                CaptureSpan { start: 2, end: 5 },
            ]
        );
        assert_eq!(first, second);

        let empty = compile_pattern("");
        let zero_width = empty
            .find_iter(
                "éa",
                IterationPolicy::NonOverlapping,
                IterationVmLimits::default(),
            )
            .expect("zero-width Unicode iteration");
        assert_eq!(
            zero_width.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 0 },
                CaptureSpan { start: 2, end: 2 },
                CaptureSpan { start: 3, end: 3 },
            ]
        );
    }

    #[test]
    fn private_compiled_pattern_limits_cancel_exactly_and_leave_it_reusable() {
        let compiled = compile_pattern("(a+)");
        let input = compiled
            .is_match(
                "four",
                CaptureVmLimits {
                    vm: VmLimits {
                        max_input_bytes: 3,
                        ..VmLimits::default()
                    },
                    ..CaptureVmLimits::default()
                },
            )
            .expect_err("input ceiling must fail closed");
        assert_eq!(input.kind, VmErrorKind::InputLimit);
        assert_eq!((input.actual, input.limit), (Some(4), Some(3)));

        let seen_keys = compiled.program.states.len() * CAPTURE_SEEN_KEYS_PER_STATE;
        let base_memory = capture_base_memory_bytes(
            seen_keys,
            seen_keys.min(DEFAULT_MAX_THREADS_PER_OFFSET),
            compiled.program.capture_slots,
            DEFAULT_MAX_TRACE_EVENTS,
        )
        .expect("bounded capture base memory");
        let memory = compiled
            .captures(
                "a",
                CaptureVmLimits {
                    vm: VmLimits {
                        max_memory_bytes: base_memory - 1,
                        ..VmLimits::default()
                    },
                    ..CaptureVmLimits::default()
                },
            )
            .expect_err("base memory ceiling must fail closed");
        assert_eq!(memory.kind, VmErrorKind::MemoryLimit);
        assert_eq!(
            (memory.actual, memory.limit),
            (Some(base_memory), Some(base_memory - 1))
        );

        let work = compiled
            .find_iter(
                "a a",
                IterationPolicy::NonOverlapping,
                IterationVmLimits {
                    capture: CaptureVmLimits {
                        vm: VmLimits {
                            max_work_units: 1,
                            ..VmLimits::default()
                        },
                        ..CaptureVmLimits::default()
                    },
                    ..IterationVmLimits::default()
                },
            )
            .expect_err("aggregate work ceiling must fail closed");
        assert_eq!(work.kind, VmErrorKind::WorkLimit);

        let match_limit = compiled
            .find_iter(
                "a a",
                IterationPolicy::NonOverlapping,
                IterationVmLimits {
                    max_matches: 1,
                    ..IterationVmLimits::default()
                },
            )
            .expect_err("second match exceeds the aggregate ceiling");
        assert_eq!(match_limit.kind, VmErrorKind::MatchLimit);
        assert_eq!((match_limit.actual, match_limit.limit), (Some(2), Some(1)));

        let private_haystack = "r3_5_probe-aaaa";
        assert_eq!(
            private_haystack.find('a'),
            Some(private_haystack.len() - 4),
            "the reuse probe must have no earlier match"
        );
        let mut probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == 3;
        let mut control =
            VmCancellationControl::new(3, &mut probe).expect("valid cancellation control");
        let cancelled = compiled
            .find_iter_with_control(
                private_haystack,
                IterationPolicy::NonOverlapping,
                IterationVmLimits::default(),
                &mut control,
            )
            .expect_err("third aggregate checkpoint cancels iteration");
        assert_eq!(cancelled.kind, VmErrorKind::Cancelled);
        assert_eq!(control.cancelled_at().map(|point| point.sequence), Some(3));
        assert!(!cancelled.to_string().contains(private_haystack));
        assert_eq!(
            compiled
                .find(private_haystack, CaptureVmLimits::default())
                .expect("compiled pattern remains reusable after cancellation"),
            Some(CaptureSpan {
                start: private_haystack.len() - 4,
                end: private_haystack.len(),
            })
        );
    }

    #[test]
    fn private_compiled_pattern_is_immutable_send_sync_for_shared_use() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PrivateCompiledPattern>();

        let compiled = std::sync::Arc::new(compile_pattern("(ab|a)"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
        let handles = (0..8)
            .map(|_| {
                let compiled = std::sync::Arc::clone(&compiled);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..32 {
                        let matched = compiled
                            .captures("zab", CaptureVmLimits::default())
                            .expect("shared capture query")
                            .expect("shared pattern matches");
                        assert_eq!(matched.span, CaptureSpan { start: 1, end: 3 });
                        assert_eq!(
                            matched.captures,
                            vec![Some(CaptureSpan { start: 1, end: 3 })]
                        );
                    }
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for handle in handles {
            handle.join().expect("shared query worker must not panic");
        }
    }

    #[test]
    fn leftmost_alternation_and_greedy_lazy_priority_are_exact() {
        let first = search("(a|ab)", "zab");
        assert_eq!(first.span, CaptureSpan { start: 1, end: 2 });
        assert_eq!(first.captures, vec![Some(CaptureSpan { start: 1, end: 2 })]);

        let longest_first = search("(ab|a)", "zab");
        assert_eq!(longest_first.span, CaptureSpan { start: 1, end: 3 });
        assert_eq!(
            longest_first.captures,
            vec![Some(CaptureSpan { start: 1, end: 3 })]
        );

        let greedy = search("(a+)", "zaaab");
        assert_eq!(greedy.span, CaptureSpan { start: 1, end: 4 });
        assert_eq!(
            greedy.captures,
            vec![Some(CaptureSpan { start: 1, end: 4 })]
        );

        let lazy = search("(a+?)", "zaaab");
        assert_eq!(lazy.span, CaptureSpan { start: 1, end: 2 });
        assert_eq!(lazy.captures, vec![Some(CaptureSpan { start: 1, end: 2 })]);
    }

    #[test]
    fn capture_participation_empty_repeated_and_unicode_spans_are_exact() {
        let unmatched = search("(a)?b", "b");
        assert_eq!(unmatched.span, CaptureSpan { start: 0, end: 1 });
        assert_eq!(unmatched.captures, vec![None]);

        let empty = search("(a*)", "");
        assert_eq!(empty.span, CaptureSpan { start: 0, end: 0 });
        assert_eq!(empty.captures, vec![Some(CaptureSpan { start: 0, end: 0 })]);

        let repeated = search("(a)+", "aaa");
        assert_eq!(repeated.span, CaptureSpan { start: 0, end: 3 });
        assert_eq!(
            repeated.captures,
            vec![Some(CaptureSpan { start: 2, end: 3 })]
        );

        let unicode = search("(é+)", "xééy");
        assert_eq!(unicode.span, CaptureSpan { start: 1, end: 5 });
        assert_eq!(
            unicode.captures,
            vec![Some(CaptureSpan { start: 1, end: 5 })]
        );
    }

    #[test]
    fn full_capture_mode_rejects_a_preferred_prefix_before_a_complete_fallback() {
        let program = lower_default("(a|ab)");
        let outcome = execute_captures_full(
            &program,
            "ab",
            CompileLimits::default(),
            CaptureVmLimits::default(),
        )
        .expect("full capture execution");
        let matched = outcome.matched.expect("fallback reaches the full end");
        assert_eq!(matched.span, CaptureSpan { start: 0, end: 2 });
        assert_eq!(
            matched.captures,
            vec![Some(CaptureSpan { start: 0, end: 2 })]
        );
    }

    #[test]
    fn capture_history_and_memory_limits_fail_closed_without_input_disclosure() {
        assert!(
            u64::try_from(core::mem::size_of::<CaptureThread>()).expect("thread size fits u64")
                <= ACCOUNTED_CAPTURE_THREAD_BYTES
        );
        assert!(
            u64::try_from(core::mem::size_of::<CaptureHistoryNode>())
                .expect("history-node size fits u64")
                <= ACCOUNTED_CAPTURE_HISTORY_NODE_BYTES
        );
        assert!(
            u64::try_from(core::mem::size_of::<usize>()).expect("key size fits u64")
                <= ACCOUNTED_CAPTURE_TOUCHED_KEY_BYTES
        );
        assert!(
            u64::try_from(core::mem::size_of::<Option<CaptureSpan>>())
                .expect("capture result size fits u64")
                <= ACCOUNTED_CAPTURE_RESULT_SLOT_BYTES * 2
        );

        let program = lower_default("(a)+");
        let history = execute_search(
            &program,
            "private-capture-canary-aaa",
            CompileLimits::default(),
            CaptureVmLimits {
                max_capture_history_nodes: 1,
                ..CaptureVmLimits::default()
            },
        )
        .expect_err("history ceiling");
        assert_eq!(history.kind, VmErrorKind::CaptureHistoryLimit);
        assert!(!history.to_string().contains("private-capture-canary"));

        let base_memory = capture_base_memory_bytes(
            program.states.len() * CAPTURE_SEEN_KEYS_PER_STATE,
            (program.states.len() * CAPTURE_SEEN_KEYS_PER_STATE)
                .min(DEFAULT_MAX_THREADS_PER_OFFSET),
            program.capture_slots,
            DEFAULT_MAX_TRACE_EVENTS,
        )
        .expect("bounded base memory");
        let memory = execute_search(
            &program,
            "a",
            CompileLimits::default(),
            CaptureVmLimits {
                vm: VmLimits {
                    max_memory_bytes: base_memory,
                    ..VmLimits::default()
                },
                ..CaptureVmLimits::default()
            },
        )
        .expect_err("first Save exceeds base-only memory");
        assert_eq!(memory.kind, VmErrorKind::MemoryLimit);
    }

    #[test]
    fn one_shot_is_match_and_iteration_adapters_preserve_captures() {
        let program = lower_default("(a)?b");
        let present = execute_search(
            &program,
            "b",
            CompileLimits::default(),
            CaptureVmLimits::default(),
        )
        .expect("one-shot match");
        assert!(present.is_match());
        assert_eq!(
            present.matched.expect("selected match").captures,
            vec![None]
        );

        let absent = execute_search(
            &program,
            "zzz",
            CompileLimits::default(),
            CaptureVmLimits::default(),
        )
        .expect("one-shot miss");
        assert!(!absent.is_match());

        let iterated = iterate("(a)?b", "b ab", IterationPolicy::NonOverlapping);
        assert_eq!(
            iterated.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 1 },
                CaptureSpan { start: 2, end: 4 },
            ]
        );
        assert_eq!(iterated.matches[0].captures, vec![None]);
        assert_eq!(
            iterated.matches[1].captures,
            vec![Some(CaptureSpan { start: 2, end: 3 })]
        );
    }

    #[test]
    fn overlap_policy_resumes_after_start_without_duplicate_matches() {
        let non_overlapping = iterate("aba", "ababa", IterationPolicy::NonOverlapping);
        assert_eq!(
            non_overlapping.replacement_spans().collect::<Vec<_>>(),
            vec![CaptureSpan { start: 0, end: 3 }]
        );

        let overlapping = iterate("aba", "ababa", IterationPolicy::Overlapping);
        assert_eq!(
            overlapping.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 3 },
                CaptureSpan { start: 2, end: 5 },
            ]
        );
        assert_eq!(overlapping.resources.overlap_advances, 2);
        assert_eq!(
            overlapping.trace.last().expect("terminal miss").matched,
            None
        );
    }

    #[test]
    fn zero_width_iteration_advances_by_complete_unicode_scalars_and_stops_at_end() {
        let first = iterate("", "éa", IterationPolicy::NonOverlapping);
        let second = iterate("", "éa", IterationPolicy::NonOverlapping);
        assert_eq!(
            first.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 0 },
                CaptureSpan { start: 2, end: 2 },
                CaptureSpan { start: 3, end: 3 },
            ]
        );
        assert_eq!(first.resources.zero_width_advances, 2);
        assert_eq!(first.resources.search_attempts, 3);
        assert_eq!(first.execution_fingerprint, second.execution_fingerprint);
        assert_eq!(first.resources, second.resources);
        assert_eq!(first.trace, second.trace);
        assert_eq!(
            first
                .trace
                .iter()
                .map(|event| event.search_start)
                .collect::<Vec<_>>(),
            vec![0, 2, 3]
        );

        let adjacent = iterate("a*", "baa", IterationPolicy::NonOverlapping);
        assert_eq!(
            adjacent.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 0 },
                CaptureSpan { start: 1, end: 3 },
            ]
        );
        let discarded = adjacent.trace.last().expect("discarded terminal empty");
        assert_eq!(discarded.matched, Some(CaptureSpan { start: 3, end: 3 }));
        assert!(discarded.discarded_adjacent_empty);
        assert_eq!(discarded.next_search_start, None);
    }

    #[test]
    fn iteration_match_work_memory_and_trace_limits_fail_closed() {
        assert!(
            u64::try_from(core::mem::size_of::<VmMatch>()).expect("match size fits")
                <= ACCOUNTED_ITERATION_MATCH_BYTES
        );
        assert!(
            u64::try_from(core::mem::size_of::<IterationTraceEvent>())
                .expect("iteration event size fits")
                <= ACCOUNTED_ITERATION_TRACE_EVENT_BYTES
        );

        let empty = lower_default("");
        let limit = execute_find_iter(
            &empty,
            "a",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits {
                max_matches: 1,
                ..IterationVmLimits::default()
            },
        )
        .expect_err("second empty match exceeds limit");
        assert_eq!(limit.kind, VmErrorKind::MatchLimit);
        assert_eq!(limit.actual, Some(2));
        assert_eq!(limit.limit, Some(1));

        let exact = execute_find_iter(
            &lower_default("a"),
            "a",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits {
                max_matches: 1,
                ..IterationVmLimits::default()
            },
        )
        .expect("one match at the exact ceiling");
        assert_eq!(exact.matches.len(), 1);

        let invalid = execute_find_iter(
            &empty,
            "",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits {
                max_matches: 0,
                ..IterationVmLimits::default()
            },
        )
        .expect_err("zero match ceiling is invalid");
        assert_eq!(invalid.kind, VmErrorKind::InvalidLimits);

        let work = execute_find_iter(
            &lower_default("a"),
            "a",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits {
                capture: CaptureVmLimits {
                    vm: VmLimits {
                        max_work_units: 1,
                        ..VmLimits::default()
                    },
                    ..CaptureVmLimits::default()
                },
                ..IterationVmLimits::default()
            },
        )
        .expect_err("aggregate work limit");
        assert_eq!(work.kind, VmErrorKind::WorkLimit);
    }

    #[test]
    fn explicit_cancellation_is_exact_private_and_leaves_programs_reusable() {
        let mut invalid_probe = |_: VmCancellationCheckpoint| false;
        let invalid = VmCancellationControl::new(0, &mut invalid_probe);
        assert!(matches!(
            invalid,
            Err(VmError {
                kind: VmErrorKind::InvalidLimits,
                ..
            })
        ));

        let full_program = lower_default("a*");
        let full_haystack = "a".repeat(64);
        let ordinary = execute_full(
            &full_program,
            &full_haystack,
            CompileLimits::default(),
            VmLimits::default(),
        )
        .expect("ordinary full execution");
        let mut never_cancel = |_: VmCancellationCheckpoint| false;
        let mut full_control = VmCancellationControl::new(7, &mut never_cancel)
            .expect("nonzero cancellation interval");
        let controlled = execute_full_with_control(
            &full_program,
            &full_haystack,
            CompileLimits::default(),
            VmLimits::default(),
            &mut full_control,
        )
        .expect("controlled full execution");
        assert_eq!(controlled, ordinary);
        assert_eq!(
            full_control.observed_work_units(),
            controlled.resources.work_units
        );
        assert!(full_control.checkpoints() > 0);
        assert_eq!(full_control.cancelled_at(), None);

        let capture_program = lower_default("(a+)");
        let private_haystack = "private-cancel-canary-aaaa";
        let mut capture_receipts = Vec::new();
        let mut cancel_capture = |checkpoint: VmCancellationCheckpoint| {
            capture_receipts.push(checkpoint);
            checkpoint.sequence == 3
        };
        let mut capture_control = VmCancellationControl::new(5, &mut cancel_capture)
            .expect("nonzero cancellation interval");
        let capture_error = execute_search_with_control(
            &capture_program,
            private_haystack,
            CompileLimits::default(),
            CaptureVmLimits::default(),
            &mut capture_control,
        )
        .expect_err("third checkpoint cancels capture search");
        assert_eq!(capture_error.kind, VmErrorKind::Cancelled);
        assert_eq!(
            capture_control.cancelled_at(),
            Some(VmCancellationCheckpoint {
                sequence: 3,
                work_units: 15,
                offset: capture_error.offset.expect("cancel offset"),
                state: capture_error.state,
            })
        );
        assert!(!capture_error.to_string().contains(private_haystack));
        assert_ne!(
            capture_control.checkpoint_fingerprint(),
            FINGERPRINT_OFFSET_BASIS
        );
        assert_eq!(capture_receipts.len(), 3);
        assert!(
            execute_search(
                &capture_program,
                private_haystack,
                CompileLimits::default(),
                CaptureVmLimits::default(),
            )
            .expect("program is reusable after cancellation")
            .is_match()
        );

        let iteration_program = lower_default("a");
        let mut first_probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == 4;
        let mut first_control =
            VmCancellationControl::new(3, &mut first_probe).expect("valid first control");
        let first_error = execute_find_iter_with_control(
            &iteration_program,
            "a a a a",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits::default(),
            &mut first_control,
        )
        .expect_err("fourth aggregate checkpoint cancels iteration");
        let first_receipt = (
            first_error,
            first_control.cancelled_at(),
            first_control.checkpoint_fingerprint(),
        );

        let mut second_probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == 4;
        let mut second_control =
            VmCancellationControl::new(3, &mut second_probe).expect("valid second control");
        let second_error = execute_find_iter_with_control(
            &iteration_program,
            "a a a a",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits::default(),
            &mut second_control,
        )
        .expect_err("replayed aggregate cancellation");
        assert_eq!(
            first_receipt,
            (
                second_error,
                second_control.cancelled_at(),
                second_control.checkpoint_fingerprint(),
            )
        );
        assert_eq!(first_receipt.0.kind, VmErrorKind::Cancelled);
        assert_eq!(
            iterate("a", "a a a a", IterationPolicy::NonOverlapping)
                .matches
                .len(),
            4
        );
    }

    #[test]
    fn empty_literals_classes_assertions_and_utf8_byte_chains_are_exact() {
        for (pattern, haystack, expected) in [
            ("", "", true),
            ("", "a", false),
            ("a", "a", true),
            ("a", "", false),
            ("é", "é", true),
            ("[a-c]+", "abc", true),
            ("[a-c]+", "abd", false),
            ("^a$", "a", true),
            ("^a$", "aa", false),
            (r"\bword\b", "word", true),
            (r"\bword\b", "sword", false),
        ] {
            assert_eq!(
                execute(pattern, haystack).is_full_match,
                expected,
                "{pattern:?} on {haystack:?}"
            );
        }

        // The R3.3 compiler only emits its validated exact-byte chain for this
        // retained case-folding path. Non-folded byte-mode escape lowering is
        // outside this VM bead and remains a compiler-terminal defer case.
        let byte_program = lower_default("(?i-u:é)");
        let exact_bytes = byte_program
            .classes
            .iter()
            .filter_map(|class| match &class.ranges {
                CanonicalRanges::Bytes(ranges) if ranges.len() == 1 => {
                    let range = ranges.first()?;
                    (range.start == range.end).then_some(range.start)
                }
                CanonicalRanges::Unicode(_) | CanonicalRanges::Bytes(_) => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(exact_bytes, "é".as_bytes());
        let byte_outcome = execute_full(
            &byte_program,
            "é",
            CompileLimits::default(),
            VmLimits::default(),
        )
        .expect("validated exact-byte chain executes");
        assert!(
            byte_outcome.is_full_match,
            "exact byte trace: {:?}",
            byte_outcome.trace
        );
    }

    #[test]
    fn epsilon_cycle_terminates_and_ordered_split_keeps_first_arrival() {
        let program = Program::checked(
            StateId::new(0),
            StateId::new(3),
            vec![
                State {
                    instruction: Instruction::Split {
                        preferred: StateId::new(1),
                        fallback: StateId::new(2),
                    },
                    source: span(),
                },
                State {
                    instruction: Instruction::Jump {
                        target: StateId::new(3),
                    },
                    source: span(),
                },
                State {
                    instruction: Instruction::Split {
                        preferred: StateId::new(0),
                        fallback: StateId::new(3),
                    },
                    source: span(),
                },
                State {
                    instruction: Instruction::Accept,
                    source: span(),
                },
            ],
            vec![],
            0,
            0,
            CompileLimits::default(),
        )
        .expect("cycle with reachable accept is valid IR");
        let outcome = execute_full(&program, "", CompileLimits::default(), VmLimits::default())
            .expect("epsilon closure terminates");
        assert!(outcome.is_full_match);
        let enqueued = outcome
            .trace
            .iter()
            .filter(|event| event.action == VmTraceAction::Enqueue)
            .map(|event| event.state.index())
            .collect::<Vec<_>>();
        assert_eq!(enqueued, vec![0, 1, 2, 3]);
        assert!(outcome.resources.deduplicated_threads >= 1);
    }

    #[test]
    fn mixed_unicode_and_byte_paths_share_a_bounded_offset_ring() {
        let program = lower_default(r"(?:é|(?i-u:é))");
        let outcome = execute_full(&program, "é", CompileLimits::default(), VmLimits::default())
            .expect("mixed path executes");
        assert!(outcome.is_full_match);
        assert!(outcome.resources.peak_threads_per_offset <= program.states.len());
        assert!(outcome.resources.accounted_memory_bytes <= DEFAULT_MAX_VM_MEMORY_BYTES);
    }

    #[test]
    fn every_vm_ceiling_fails_closed_before_partial_outcome() {
        let program = lower_default("(?:a|b|c)");
        let invalid = execute_full(
            &program,
            "a",
            CompileLimits::default(),
            VmLimits {
                max_input_bytes: 0,
                ..VmLimits::default()
            },
        )
        .expect_err("invalid limits");
        assert_eq!(invalid.kind, VmErrorKind::InvalidLimits);

        let input = execute_full(
            &program,
            "aa",
            CompileLimits::default(),
            VmLimits {
                max_input_bytes: 1,
                ..VmLimits::default()
            },
        )
        .expect_err("input ceiling");
        assert_eq!(input.kind, VmErrorKind::InputLimit);

        let threads = execute_full(
            &program,
            "a",
            CompileLimits::default(),
            VmLimits {
                max_threads_per_offset: 1,
                ..VmLimits::default()
            },
        )
        .expect_err("thread ceiling");
        assert_eq!(threads.kind, VmErrorKind::ThreadLimit);

        let memory = execute_full(
            &program,
            "a",
            CompileLimits::default(),
            VmLimits {
                max_memory_bytes: ACCOUNTED_VM_BASE_BYTES,
                ..VmLimits::default()
            },
        )
        .expect_err("memory ceiling");
        assert_eq!(memory.kind, VmErrorKind::MemoryLimit);

        let work = execute_full(
            &program,
            "a",
            CompileLimits::default(),
            VmLimits {
                max_work_units: 1,
                ..VmLimits::default()
            },
        )
        .expect_err("work ceiling");
        assert_eq!(work.kind, VmErrorKind::WorkLimit);
    }

    #[test]
    fn malformed_ir_is_rejected_by_r3_3_before_vm_allocation() {
        let mut program = lower_default("a");
        program.states[0].instruction = Instruction::Jump {
            target: StateId::new(usize::MAX),
        };
        let error = execute_full(&program, "a", CompileLimits::default(), VmLimits::default())
            .expect_err("invalid target must fail validation");
        assert_eq!(
            error.kind,
            VmErrorKind::Compile(CompileErrorKind::InvalidTarget)
        );
    }

    #[test]
    fn long_input_is_linear_deterministic_and_trace_bounded() {
        let program = lower_default("a*");
        let haystack = "a".repeat(10_000);
        let first = execute_full(
            &program,
            &haystack,
            CompileLimits::default(),
            VmLimits::default(),
        )
        .expect("long input");
        let second = execute_full(
            &program,
            &haystack,
            CompileLimits::default(),
            VmLimits::default(),
        )
        .expect("deterministic replay");
        assert!(first.is_full_match);
        assert_eq!(first.execution_fingerprint, second.execution_fingerprint);
        assert_eq!(first.resources, second.resources);
        assert!(first.trace_truncated);
        assert_eq!(first.trace.len(), DEFAULT_MAX_TRACE_EVENTS);
        let state_bound = u64::try_from(program.states.len()).expect("state count fits u64");
        let input_bound = u64::try_from(haystack.len() + 1).expect("input fits u64");
        assert!(first.resources.state_visits <= state_bound * input_bound);
    }

    #[test]
    fn error_display_is_pattern_and_haystack_free() {
        let private = "private-vm-canary";
        let program = lower_default("a");
        let error = execute_full(
            &program,
            private,
            CompileLimits::default(),
            VmLimits {
                max_input_bytes: 1,
                ..VmLimits::default()
            },
        )
        .expect_err("input ceiling");
        let rendered = error.to_string();
        assert!(rendered.starts_with("[RGX-VM-E002]"));
        assert!(!rendered.contains(private));
        assert_eq!(program.schema_version, IR_SCHEMA_VERSION);
    }
}
