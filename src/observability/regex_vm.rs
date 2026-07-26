//! Strictly safe, resource-bounded Thompson-IR execution.
//!
//! This private R3.4.1 surface executes only programs that pass the R3.3
//! validator. It implements whole-haystack language recognition with ordered
//! epsilon closure. Leftmost search, capture propagation, iteration APIs,
//! cancellation, production privacy wiring, and dependency replacement remain
//! downstream work.

use core::fmt;

use super::regex_boundaries::BoundaryEvalErrorKind;
use super::regex_ir::{
    ClassId, CompileError, CompileErrorKind, CompileLimits, Instruction, Program, StateId,
};
use super::regex_semantics::{ByteRange, CanonicalRanges, ScalarRange};

pub const VM_ID: &str = "ASUP-REGEX-THREAD-SET-VM-V1";
pub const VM_SCHEMA_VERSION: u16 = 1;

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

struct Executor<'program, 'haystack> {
    program: &'program Program,
    haystack: &'haystack str,
    limits: VmLimits,
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

impl<'program, 'haystack> Executor<'program, 'haystack> {
    fn new(
        program: &'program Program,
        haystack: &'haystack str,
        limits: VmLimits,
        thread_capacity: usize,
        accounted_memory_bytes: u64,
    ) -> Self {
        Self {
            program,
            haystack,
            limits,
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

    fn span() -> SourceSpan {
        SourceSpan {
            byte_start: 0,
            byte_end: 0,
            scalar_start: 0,
            scalar_end: 0,
        }
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
