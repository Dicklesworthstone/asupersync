//! Strictly safe, resource-bounded Thompson-IR execution.
//!
//! This private R3.4 surface executes only programs that pass the R3.3
//! validator. The R3.4.1 entry point implements whole-haystack language
//! recognition. The R3.4.2 entry points add one-shot leftmost-first selection,
//! ordered greedy/lazy execution, and bounded capture histories. R3.4.3 adds
//! deterministic match/capture iteration, explicit overlap policy, Unicode-safe
//! zero-width progress, and ordered replacement spans. R3.4.4 adds explicit
//! caller-supplied cancellation checkpoints and terminal adversarial evidence.
//! Production privacy wiring, replacement-template syntax, and dependency
//! replacement remain downstream work.

use core::fmt;

use super::regex_boundaries::BoundaryEvalErrorKind;
use super::regex_ir::{
    CaptureSlot, ClassId, CompileError, CompileErrorKind, CompileLimits, Instruction, Program,
    StateId,
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

const FINGERPRINT_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FINGERPRINT_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
