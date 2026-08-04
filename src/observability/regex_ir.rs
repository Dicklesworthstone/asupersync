//! Versioned, resource-bounded Thompson IR for the candidate regex compiler.
//!
//! This private staging surface defines the representation consumed by the
//! R3.3 compiler and validator work. It does not lower syntax, execute a
//! matcher, persist programs, or replace the incumbent regex dependency.

use core::fmt;

use serde_json::{Value, json};

use super::regex_boundaries::BoundaryKind;
use super::regex_semantics::CanonicalRanges;
use super::regex_syntax::SourceSpan;

pub const IR_ID: &str = "ASUP-REGEX-THOMPSON-IR-V1";
pub const IR_SCHEMA_VERSION: u16 = 1;
pub const DIAGNOSTIC_SCHEMA_ID: &str = "asupersync-regex-thompson-ir-diagnostic-v1";
pub const PERSISTENCE_POLICY: &str = "diagnostic-only-no-deserialization-contract";

pub const DEFAULT_MAX_STATES: usize = 262_144;
pub const DEFAULT_MAX_TRANSITIONS: usize = 524_288;
pub const DEFAULT_MAX_CLASSES: usize = 65_536;
pub const DEFAULT_MAX_RANGES_PER_CLASS: usize = 4_096;
pub const DEFAULT_MAX_TOTAL_CLASS_RANGES: usize = 1_048_576;
pub const DEFAULT_MAX_CAPTURE_SLOTS: usize = 4_096;
pub const DEFAULT_MAX_REPETITION_EXPANSION: u64 = 1_048_576;
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_MAX_WORK_UNITS: u64 = 8_388_608;

// These are schema-accounting constants, not `size_of` results. Keeping them
// explicit makes receipts identical across target architectures and compiler
// versions. They intentionally include allocator and vector capacity headroom.
pub const ACCOUNTED_PROGRAM_BYTES: u64 = 64;
pub const ACCOUNTED_STATE_BYTES: u64 = 48;
pub const ACCOUNTED_CLASS_BYTES: u64 = 32;
pub const ACCOUNTED_CLASS_RANGE_BYTES: u64 = 8;
pub const ACCOUNTED_CAPTURE_SLOT_BYTES: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileLimits {
    pub max_states: usize,
    pub max_transitions: usize,
    pub max_classes: usize,
    pub max_ranges_per_class: usize,
    pub max_total_class_ranges: usize,
    pub max_capture_slots: usize,
    pub max_repetition_expansion: u64,
    pub max_memory_bytes: u64,
    pub max_work_units: u64,
}

impl Default for CompileLimits {
    fn default() -> Self {
        Self {
            max_states: DEFAULT_MAX_STATES,
            max_transitions: DEFAULT_MAX_TRANSITIONS,
            max_classes: DEFAULT_MAX_CLASSES,
            max_ranges_per_class: DEFAULT_MAX_RANGES_PER_CLASS,
            max_total_class_ranges: DEFAULT_MAX_TOTAL_CLASS_RANGES,
            max_capture_slots: DEFAULT_MAX_CAPTURE_SLOTS,
            max_repetition_expansion: DEFAULT_MAX_REPETITION_EXPANSION,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_work_units: DEFAULT_MAX_WORK_UNITS,
        }
    }
}

impl CompileLimits {
    fn invariants_hold(self) -> bool {
        self.max_states > 0
            && self.max_transitions > 0
            && self.max_classes > 0
            && self.max_ranges_per_class > 0
            && self.max_total_class_ranges > 0
            && self.max_capture_slots > 0
            && self.max_repetition_expansion > 0
            && self.max_memory_bytes >= ACCOUNTED_PROGRAM_BYTES
            && self.max_work_units > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StateId(usize);

impl StateId {
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    pub const fn index(self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClassId(usize);

impl ClassId {
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    pub const fn index(self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaptureSlot(usize);

impl CaptureSlot {
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    pub const fn index(self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    /// The sole terminal state.
    Accept,
    /// Unconditional epsilon transition.
    Jump { target: StateId },
    /// Ordered epsilon fork. `preferred` is scheduled before `fallback`.
    Split {
        preferred: StateId,
        fallback: StateId,
    },
    /// Consume one class element and continue.
    Consume { class: ClassId, target: StateId },
    /// Test a zero-width assertion and continue without consuming input.
    Assert { kind: BoundaryKind, target: StateId },
    /// Save the current input offset into an even/odd capture boundary slot.
    Save { slot: CaptureSlot, target: StateId },
}

impl Instruction {
    pub const fn transition_count(&self) -> usize {
        match self {
            Self::Accept => 0,
            Self::Split { .. } => 2,
            Self::Jump { .. } | Self::Consume { .. } | Self::Assert { .. } | Self::Save { .. } => 1,
        }
    }

    fn targets(&self) -> [Option<StateId>; 2] {
        match *self {
            Self::Accept => [None, None],
            Self::Jump { target }
            | Self::Consume { target, .. }
            | Self::Assert { target, .. }
            | Self::Save { target, .. } => [Some(target), None],
            Self::Split {
                preferred,
                fallback,
            } => [Some(preferred), Some(fallback)],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub instruction: Instruction,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrClass {
    pub ranges: CanonicalRanges,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileResources {
    pub states: usize,
    pub transitions: usize,
    pub classes: usize,
    pub class_ranges: usize,
    pub capture_slots: usize,
    pub repetition_expansion: u64,
    pub accounted_memory_bytes: u64,
    pub work_units: u64,
}

impl CompileResources {
    fn checked(
        states: &[State],
        classes: &[IrClass],
        capture_slots: usize,
        repetition_expansion: u64,
    ) -> Result<Self, CompileError> {
        let transitions = states.iter().try_fold(0_usize, |total, state| {
            total
                .checked_add(state.instruction.transition_count())
                .ok_or_else(CompileError::arithmetic_overflow)
        })?;
        let class_ranges = classes.iter().try_fold(0_usize, |total, class| {
            total
                .checked_add(class.ranges.range_count())
                .ok_or_else(CompileError::arithmetic_overflow)
        })?;

        let state_count =
            u64::try_from(states.len()).map_err(|_| CompileError::arithmetic_overflow())?;
        let class_count =
            u64::try_from(classes.len()).map_err(|_| CompileError::arithmetic_overflow())?;
        let range_count =
            u64::try_from(class_ranges).map_err(|_| CompileError::arithmetic_overflow())?;
        let slot_count =
            u64::try_from(capture_slots).map_err(|_| CompileError::arithmetic_overflow())?;
        let transition_count =
            u64::try_from(transitions).map_err(|_| CompileError::arithmetic_overflow())?;

        let accounted_memory_bytes = ACCOUNTED_PROGRAM_BYTES
            .checked_add(
                state_count
                    .checked_mul(ACCOUNTED_STATE_BYTES)
                    .ok_or_else(CompileError::arithmetic_overflow)?,
            )
            .and_then(|total| {
                class_count
                    .checked_mul(ACCOUNTED_CLASS_BYTES)
                    .and_then(|bytes| total.checked_add(bytes))
            })
            .and_then(|total| {
                range_count
                    .checked_mul(ACCOUNTED_CLASS_RANGE_BYTES)
                    .and_then(|bytes| total.checked_add(bytes))
            })
            .and_then(|total| {
                slot_count
                    .checked_mul(ACCOUNTED_CAPTURE_SLOT_BYTES)
                    .and_then(|bytes| total.checked_add(bytes))
            })
            .ok_or_else(CompileError::arithmetic_overflow)?;

        let work_units = 1_u64
            .checked_add(state_count)
            .and_then(|total| total.checked_add(transition_count))
            .and_then(|total| total.checked_add(class_count))
            .and_then(|total| total.checked_add(range_count))
            .and_then(|total| total.checked_add(slot_count))
            .and_then(|total| total.checked_add(repetition_expansion))
            .ok_or_else(CompileError::arithmetic_overflow)?;

        Ok(Self {
            states: states.len(),
            transitions,
            classes: classes.len(),
            class_ranges,
            capture_slots,
            repetition_expansion,
            accounted_memory_bytes,
            work_units,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub schema_version: u16,
    pub ir_id: &'static str,
    pub entry: StateId,
    pub accept: StateId,
    pub states: Vec<State>,
    pub classes: Vec<IrClass>,
    /// Capture boundary slot count. Slots are paired start/end, so this is even.
    pub capture_slots: usize,
    /// Number of compiler-emitted repetition copies, not a match-time counter.
    pub repetition_expansion: u64,
    pub resources: CompileResources,
}

impl Program {
    pub fn checked(
        entry: StateId,
        accept: StateId,
        states: Vec<State>,
        classes: Vec<IrClass>,
        capture_slots: usize,
        repetition_expansion: u64,
        limits: CompileLimits,
    ) -> Result<Self, CompileError> {
        let resources =
            CompileResources::checked(&states, &classes, capture_slots, repetition_expansion)?;
        let program = Self {
            schema_version: IR_SCHEMA_VERSION,
            ir_id: IR_ID,
            entry,
            accept,
            states,
            classes,
            capture_slots,
            repetition_expansion,
            resources,
        };
        program.validate(limits)?;
        Ok(program)
    }

    pub fn validate(&self, limits: CompileLimits) -> Result<(), CompileError> {
        if !limits.invariants_hold() {
            return Err(CompileError::new(CompileErrorKind::InvalidLimits));
        }
        if self.schema_version != IR_SCHEMA_VERSION || self.ir_id != IR_ID {
            return Err(CompileError::new(CompileErrorKind::InvalidSchema));
        }
        if self.states.is_empty() {
            return Err(CompileError::new(CompileErrorKind::EmptyProgram));
        }

        check_limit(
            CompileErrorKind::StateLimit,
            self.states.len(),
            limits.max_states,
        )?;
        check_limit(
            CompileErrorKind::ClassLimit,
            self.classes.len(),
            limits.max_classes,
        )?;
        check_limit(
            CompileErrorKind::CaptureSlotLimit,
            self.capture_slots,
            limits.max_capture_slots,
        )?;
        if self.capture_slots % 2 != 0 {
            return Err(CompileError::new(CompileErrorKind::OddCaptureSlots)
                .with_actual_limit(self.capture_slots, self.capture_slots.saturating_add(1)));
        }
        check_u64_limit(
            CompileErrorKind::RepetitionLimit,
            self.repetition_expansion,
            limits.max_repetition_expansion,
        )?;

        let resources = CompileResources::checked(
            &self.states,
            &self.classes,
            self.capture_slots,
            self.repetition_expansion,
        )?;
        check_limit(
            CompileErrorKind::TransitionLimit,
            resources.transitions,
            limits.max_transitions,
        )?;
        check_limit(
            CompileErrorKind::TotalClassRangeLimit,
            resources.class_ranges,
            limits.max_total_class_ranges,
        )?;
        check_u64_limit(
            CompileErrorKind::MemoryLimit,
            resources.accounted_memory_bytes,
            limits.max_memory_bytes,
        )?;
        check_u64_limit(
            CompileErrorKind::WorkLimit,
            resources.work_units,
            limits.max_work_units,
        )?;
        if resources != self.resources {
            return Err(CompileError::new(
                CompileErrorKind::ResourceAccountingMismatch,
            ));
        }

        if self.entry.index() >= self.states.len() {
            return Err(CompileError::new(CompileErrorKind::InvalidEntry).with_state(self.entry));
        }
        if self.accept.index() >= self.states.len() {
            return Err(CompileError::new(CompileErrorKind::InvalidAccept).with_state(self.accept));
        }
        if !matches!(
            self.states[self.accept.index()].instruction,
            Instruction::Accept
        ) {
            return Err(CompileError::new(CompileErrorKind::AcceptNotTerminal)
                .with_state(self.accept)
                .with_span(self.states[self.accept.index()].source));
        }

        let mut referenced_classes = vec![false; self.classes.len()];
        let mut referenced_slots = vec![false; self.capture_slots];
        for (index, state) in self.states.iter().enumerate() {
            let state_id = StateId::new(index);
            if !span_is_well_formed(state.source) {
                return Err(CompileError::new(CompileErrorKind::InvalidSpan)
                    .with_state(state_id)
                    .with_span(state.source));
            }
            if matches!(state.instruction, Instruction::Accept) && state_id != self.accept {
                return Err(CompileError::new(CompileErrorKind::ExtraAcceptState)
                    .with_state(state_id)
                    .with_span(state.source));
            }
            for target in state.instruction.targets().into_iter().flatten() {
                if target.index() >= self.states.len() {
                    return Err(CompileError::new(CompileErrorKind::InvalidTarget)
                        .with_state(state_id)
                        .with_span(state.source)
                        .with_actual_limit(target.index(), self.states.len()));
                }
            }
            match state.instruction {
                Instruction::Consume { class, .. } => {
                    let Some(referenced) = referenced_classes.get_mut(class.index()) else {
                        return Err(CompileError::new(CompileErrorKind::InvalidClassReference)
                            .with_state(state_id)
                            .with_class(class)
                            .with_span(state.source));
                    };
                    *referenced = true;
                }
                Instruction::Save { slot, .. } => {
                    let Some(referenced) = referenced_slots.get_mut(slot.index()) else {
                        return Err(CompileError::new(CompileErrorKind::InvalidCaptureSlot)
                            .with_state(state_id)
                            .with_slot(slot)
                            .with_span(state.source));
                    };
                    *referenced = true;
                }
                Instruction::Accept
                | Instruction::Jump { .. }
                | Instruction::Split { .. }
                | Instruction::Assert { .. } => {}
            }
        }

        for (index, class) in self.classes.iter().enumerate() {
            let class_id = ClassId::new(index);
            if !span_is_well_formed(class.source) {
                return Err(CompileError::new(CompileErrorKind::InvalidSpan)
                    .with_class(class_id)
                    .with_span(class.source));
            }
            check_limit(
                CompileErrorKind::ClassRangeLimit,
                class.ranges.range_count(),
                limits.max_ranges_per_class,
            )
            .map_err(|error| error.with_class(class_id).with_span(class.source))?;
            if !class.ranges.is_canonical() {
                return Err(CompileError::new(CompileErrorKind::NonCanonicalClass)
                    .with_class(class_id)
                    .with_span(class.source));
            }
        }

        if let Some(index) = referenced_classes.iter().position(|referenced| !referenced) {
            return Err(CompileError::new(CompileErrorKind::UnreferencedClass)
                .with_class(ClassId::new(index))
                .with_span(self.classes[index].source));
        }
        if let Some(index) = referenced_slots.iter().position(|referenced| !referenced) {
            return Err(CompileError::new(CompileErrorKind::UnreferencedCaptureSlot)
                .with_slot(CaptureSlot::new(index)));
        }

        let mut reachable = vec![false; self.states.len()];
        let mut pending = vec![self.entry];
        while let Some(state_id) = pending.pop() {
            if reachable[state_id.index()] {
                continue;
            }
            reachable[state_id.index()] = true;
            pending.extend(
                self.states[state_id.index()]
                    .instruction
                    .targets()
                    .into_iter()
                    .flatten()
                    .filter(|target| !reachable[target.index()]),
            );
        }
        if !reachable[self.accept.index()] {
            return Err(
                CompileError::new(CompileErrorKind::AcceptUnreachable).with_state(self.accept)
            );
        }
        if let Some(index) = reachable.iter().position(|visited| !visited) {
            return Err(CompileError::new(CompileErrorKind::UnreachableState)
                .with_state(StateId::new(index))
                .with_span(self.states[index].source));
        }

        Ok(())
    }

    /// Emit a stable, pattern-free debug snapshot.
    ///
    /// The capability registry does not declare an IR persistence contract.
    /// This value therefore has no decoder and must not be stored as executable
    /// input or treated as a cross-version compatibility promise.
    pub fn diagnostic_json(&self) -> Value {
        json!({
            "schema_id": DIAGNOSTIC_SCHEMA_ID,
            "schema_version": self.schema_version,
            "ir_id": self.ir_id,
            "persistence_policy": PERSISTENCE_POLICY,
            "entry": self.entry.index(),
            "accept": self.accept.index(),
            "capture_slots": self.capture_slots,
            "repetition_expansion": self.repetition_expansion,
            "resources": resources_json(self.resources),
            "classes": self.classes.iter().map(class_json).collect::<Vec<_>>(),
            "states": self.states.iter().map(state_json).collect::<Vec<_>>(),
        })
    }
}

fn check_limit(kind: CompileErrorKind, actual: usize, limit: usize) -> Result<(), CompileError> {
    if actual > limit {
        Err(CompileError::new(kind).with_actual_limit(actual, limit))
    } else {
        Ok(())
    }
}

fn check_u64_limit(kind: CompileErrorKind, actual: u64, limit: u64) -> Result<(), CompileError> {
    if actual > limit {
        Err(CompileError::new(kind).with_actual_limit(actual, limit))
    } else {
        Ok(())
    }
}

fn span_is_well_formed(span: SourceSpan) -> bool {
    let byte_width = span.byte_end.checked_sub(span.byte_start);
    let scalar_width = span.scalar_end.checked_sub(span.scalar_start);
    matches!(
        (byte_width, scalar_width),
        (Some(bytes), Some(scalars))
            if (bytes == 0) == (scalars == 0) && scalars <= bytes
    )
}

fn span_json(span: SourceSpan) -> Value {
    json!({
        "byte_start": span.byte_start,
        "byte_end": span.byte_end,
        "scalar_start": span.scalar_start,
        "scalar_end": span.scalar_end,
    })
}

fn resources_json(resources: CompileResources) -> Value {
    json!({
        "states": resources.states,
        "transitions": resources.transitions,
        "classes": resources.classes,
        "class_ranges": resources.class_ranges,
        "capture_slots": resources.capture_slots,
        "repetition_expansion": resources.repetition_expansion,
        "accounted_memory_bytes": resources.accounted_memory_bytes,
        "work_units": resources.work_units,
    })
}

fn class_json(class: &IrClass) -> Value {
    let (alphabet, ranges) = match &class.ranges {
        CanonicalRanges::Unicode(ranges) => (
            "unicode-scalar",
            ranges
                .iter()
                .map(|range| {
                    json!({
                        "start": u32::from(range.start),
                        "end": u32::from(range.end),
                    })
                })
                .collect::<Vec<_>>(),
        ),
        CanonicalRanges::Bytes(ranges) => (
            "utf8-safe-byte",
            ranges
                .iter()
                .map(|range| {
                    json!({
                        "start": range.start,
                        "end": range.end,
                    })
                })
                .collect::<Vec<_>>(),
        ),
    };
    json!({
        "alphabet": alphabet,
        "source": span_json(class.source),
        "ranges": ranges,
    })
}

fn state_json(state: &State) -> Value {
    let instruction = match state.instruction {
        Instruction::Accept => json!({"op": "accept"}),
        Instruction::Jump { target } => {
            json!({"op": "jump", "target": target.index()})
        }
        Instruction::Split {
            preferred,
            fallback,
        } => json!({
            "op": "split",
            "preferred": preferred.index(),
            "fallback": fallback.index(),
        }),
        Instruction::Consume { class, target } => json!({
            "op": "consume",
            "class": class.index(),
            "target": target.index(),
        }),
        Instruction::Assert { kind, target } => json!({
            "op": "assert",
            "kind": boundary_name(kind),
            "target": target.index(),
        }),
        Instruction::Save { slot, target } => json!({
            "op": "save",
            "slot": slot.index(),
            "target": target.index(),
        }),
    };
    json!({
        "source": span_json(state.source),
        "instruction": instruction,
    })
}

const fn boundary_name(kind: BoundaryKind) -> &'static str {
    match kind {
        BoundaryKind::InputStart => "input-start",
        BoundaryKind::InputEnd => "input-end",
        BoundaryKind::LineStartLf => "line-start-lf",
        BoundaryKind::LineEndLf => "line-end-lf",
        BoundaryKind::LineStartCrlf => "line-start-crlf",
        BoundaryKind::LineEndCrlf => "line-end-crlf",
        BoundaryKind::WordAscii => "word-ascii",
        BoundaryKind::NotWordAscii => "not-word-ascii",
        BoundaryKind::WordUnicode => "word-unicode",
        BoundaryKind::NotWordUnicode => "not-word-unicode",
        BoundaryKind::WordStartAscii => "word-start-ascii",
        BoundaryKind::WordEndAscii => "word-end-ascii",
        BoundaryKind::WordStartUnicode => "word-start-unicode",
        BoundaryKind::WordEndUnicode => "word-end-unicode",
        BoundaryKind::WordStartHalfAscii => "word-start-half-ascii",
        BoundaryKind::WordEndHalfAscii => "word-end-half-ascii",
        BoundaryKind::WordStartHalfUnicode => "word-start-half-unicode",
        BoundaryKind::WordEndHalfUnicode => "word-end-half-unicode",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileErrorKind {
    InvalidLimits,
    InvalidSchema,
    ArithmeticOverflow,
    EmptyProgram,
    StateLimit,
    TransitionLimit,
    ClassLimit,
    ClassRangeLimit,
    TotalClassRangeLimit,
    CaptureSlotLimit,
    OddCaptureSlots,
    RepetitionLimit,
    MemoryLimit,
    WorkLimit,
    ResourceAccountingMismatch,
    InvalidEntry,
    InvalidAccept,
    AcceptNotTerminal,
    ExtraAcceptState,
    InvalidTarget,
    InvalidClassReference,
    InvalidCaptureSlot,
    InvalidSpan,
    NonCanonicalClass,
    UnreferencedClass,
    UnreferencedCaptureSlot,
    AcceptUnreachable,
    UnreachableState,
}

impl CompileErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "RGX-IR-E001",
            Self::InvalidSchema => "RGX-IR-E002",
            Self::ArithmeticOverflow => "RGX-IR-E003",
            Self::EmptyProgram => "RGX-IR-E004",
            Self::StateLimit => "RGX-IR-E005",
            Self::TransitionLimit => "RGX-IR-E006",
            Self::ClassLimit => "RGX-IR-E007",
            Self::ClassRangeLimit => "RGX-IR-E008",
            Self::TotalClassRangeLimit => "RGX-IR-E009",
            Self::CaptureSlotLimit => "RGX-IR-E010",
            Self::OddCaptureSlots => "RGX-IR-E011",
            Self::RepetitionLimit => "RGX-IR-E012",
            Self::MemoryLimit => "RGX-IR-E013",
            Self::WorkLimit => "RGX-IR-E014",
            Self::ResourceAccountingMismatch => "RGX-IR-E015",
            Self::InvalidEntry => "RGX-IR-E016",
            Self::InvalidAccept => "RGX-IR-E017",
            Self::AcceptNotTerminal => "RGX-IR-E018",
            Self::ExtraAcceptState => "RGX-IR-E019",
            Self::InvalidTarget => "RGX-IR-E020",
            Self::InvalidClassReference => "RGX-IR-E021",
            Self::InvalidCaptureSlot => "RGX-IR-E022",
            Self::InvalidSpan => "RGX-IR-E023",
            Self::NonCanonicalClass => "RGX-IR-E024",
            Self::UnreferencedClass => "RGX-IR-E025",
            Self::UnreferencedCaptureSlot => "RGX-IR-E026",
            Self::AcceptUnreachable => "RGX-IR-E027",
            Self::UnreachableState => "RGX-IR-E028",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub kind: CompileErrorKind,
    pub state: Option<StateId>,
    pub class: Option<ClassId>,
    pub slot: Option<CaptureSlot>,
    pub span: Option<SourceSpan>,
    pub actual: Option<u64>,
    pub limit: Option<u64>,
}

impl CompileError {
    fn new(kind: CompileErrorKind) -> Self {
        Self {
            kind,
            state: None,
            class: None,
            slot: None,
            span: None,
            actual: None,
            limit: None,
        }
    }

    fn arithmetic_overflow() -> Self {
        Self::new(CompileErrorKind::ArithmeticOverflow)
    }

    fn with_state(mut self, state: StateId) -> Self {
        self.state = Some(state);
        self
    }

    fn with_class(mut self, class: ClassId) -> Self {
        self.class = Some(class);
        self
    }

    fn with_slot(mut self, slot: CaptureSlot) -> Self {
        self.slot = Some(slot);
        self
    }

    fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = Some(span);
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

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{}] {:?}", self.code(), self.kind)?;
        if let Some(state) = self.state {
            write!(formatter, " state={}", state.index())?;
        }
        if let Some(class) = self.class {
            write!(formatter, " class={}", class.index())?;
        }
        if let Some(slot) = self.slot {
            write!(formatter, " slot={}", slot.index())?;
        }
        if let Some(span) = self.span {
            write!(
                formatter,
                " bytes={}..{} scalars={}..{}",
                span.byte_start, span.byte_end, span.scalar_start, span.scalar_end
            )?;
        }
        if let (Some(actual), Some(limit)) = (self.actual, self.limit) {
            write!(formatter, " actual={actual} limit={limit}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CompileError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::regex_semantics::{ByteRange, ScalarRange};

    const EMPTY_SPAN: SourceSpan = SourceSpan {
        byte_start: 0,
        byte_end: 0,
        scalar_start: 0,
        scalar_end: 0,
    };
    const ONE_SPAN: SourceSpan = SourceSpan {
        byte_start: 0,
        byte_end: 1,
        scalar_start: 0,
        scalar_end: 1,
    };

    fn literal_program() -> Program {
        Program::checked(
            StateId::new(0),
            StateId::new(1),
            vec![
                State {
                    instruction: Instruction::Consume {
                        class: ClassId::new(0),
                        target: StateId::new(1),
                    },
                    source: ONE_SPAN,
                },
                State {
                    instruction: Instruction::Accept,
                    source: EMPTY_SPAN,
                },
            ],
            vec![IrClass {
                ranges: CanonicalRanges::Unicode(vec![ScalarRange::new('a', 'a')]),
                source: ONE_SPAN,
            }],
            0,
            0,
            CompileLimits::default(),
        )
        .expect("literal program must be valid")
    }

    fn capture_split_program() -> Program {
        Program::checked(
            StateId::new(0),
            StateId::new(6),
            vec![
                State {
                    instruction: Instruction::Save {
                        slot: CaptureSlot::new(0),
                        target: StateId::new(1),
                    },
                    source: EMPTY_SPAN,
                },
                State {
                    instruction: Instruction::Split {
                        preferred: StateId::new(2),
                        fallback: StateId::new(4),
                    },
                    source: ONE_SPAN,
                },
                State {
                    instruction: Instruction::Consume {
                        class: ClassId::new(0),
                        target: StateId::new(3),
                    },
                    source: ONE_SPAN,
                },
                State {
                    instruction: Instruction::Jump {
                        target: StateId::new(5),
                    },
                    source: EMPTY_SPAN,
                },
                State {
                    instruction: Instruction::Assert {
                        kind: BoundaryKind::InputStart,
                        target: StateId::new(5),
                    },
                    source: EMPTY_SPAN,
                },
                State {
                    instruction: Instruction::Save {
                        slot: CaptureSlot::new(1),
                        target: StateId::new(6),
                    },
                    source: EMPTY_SPAN,
                },
                State {
                    instruction: Instruction::Accept,
                    source: EMPTY_SPAN,
                },
            ],
            vec![IrClass {
                ranges: CanonicalRanges::Bytes(vec![ByteRange::new(b'a', b'z')]),
                source: ONE_SPAN,
            }],
            2,
            0,
            CompileLimits::default(),
        )
        .expect("capture/split program must be valid")
    }

    #[test]
    fn checked_accepts_empty_literal_and_full_instruction_surface() {
        let empty = Program::checked(
            StateId::new(0),
            StateId::new(0),
            vec![State {
                instruction: Instruction::Accept,
                source: EMPTY_SPAN,
            }],
            vec![],
            0,
            0,
            CompileLimits::default(),
        )
        .expect("empty expression program");
        empty
            .validate(CompileLimits::default())
            .expect("empty expression validates");
        literal_program()
            .validate(CompileLimits::default())
            .expect("literal validates");
        let full = capture_split_program();
        full.validate(CompileLimits::default())
            .expect("all instruction variants validate");
        assert_eq!(full.resources.states, 7);
        assert_eq!(full.resources.transitions, 7);
        assert_eq!(full.resources.capture_slots, 2);
    }

    #[test]
    fn accounting_is_target_independent_and_checked() {
        let program = literal_program();
        assert_eq!(
            program.resources,
            CompileResources {
                states: 2,
                transitions: 1,
                classes: 1,
                class_ranges: 1,
                capture_slots: 0,
                repetition_expansion: 0,
                accounted_memory_bytes: 200,
                work_units: 6,
            }
        );
        let mut tampered = program;
        tampered.resources.work_units += 1;
        assert_eq!(
            tampered
                .validate(CompileLimits::default())
                .expect_err("tampered accounting must fail")
                .kind,
            CompileErrorKind::ResourceAccountingMismatch
        );
    }

    #[test]
    fn diagnostic_golden_is_versioned_pattern_free_and_nonpersistent() {
        let diagnostic = literal_program().diagnostic_json();
        assert_eq!(
            diagnostic,
            json!({
                "schema_id": "asupersync-regex-thompson-ir-diagnostic-v1",
                "schema_version": 1,
                "ir_id": "ASUP-REGEX-THOMPSON-IR-V1",
                "persistence_policy": "diagnostic-only-no-deserialization-contract",
                "entry": 0,
                "accept": 1,
                "capture_slots": 0,
                "repetition_expansion": 0,
                "resources": {
                    "states": 2,
                    "transitions": 1,
                    "classes": 1,
                    "class_ranges": 1,
                    "capture_slots": 0,
                    "repetition_expansion": 0,
                    "accounted_memory_bytes": 200,
                    "work_units": 6,
                },
                "classes": [{
                    "alphabet": "unicode-scalar",
                    "source": {
                        "byte_start": 0,
                        "byte_end": 1,
                        "scalar_start": 0,
                        "scalar_end": 1,
                    },
                    "ranges": [{"start": 97, "end": 97}],
                }],
                "states": [
                    {
                        "source": {
                            "byte_start": 0,
                            "byte_end": 1,
                            "scalar_start": 0,
                            "scalar_end": 1,
                        },
                        "instruction": {"op": "consume", "class": 0, "target": 1},
                    },
                    {
                        "source": {
                            "byte_start": 0,
                            "byte_end": 0,
                            "scalar_start": 0,
                            "scalar_end": 0,
                        },
                        "instruction": {"op": "accept"},
                    },
                ],
            })
        );
        let text = diagnostic.to_string();
        assert!(!text.contains("pattern"));
        assert!(text.contains(PERSISTENCE_POLICY));
    }

    #[test]
    fn malformed_graph_targets_classes_slots_and_accepts_are_rejected() {
        let mut invalid_target = literal_program();
        invalid_target.states[0].instruction = Instruction::Jump {
            target: StateId::new(99),
        };
        assert_eq!(
            invalid_target
                .validate(CompileLimits::default())
                .expect_err("invalid target")
                .kind,
            CompileErrorKind::InvalidTarget
        );

        let mut invalid_class = literal_program();
        invalid_class.states[0].instruction = Instruction::Consume {
            class: ClassId::new(9),
            target: StateId::new(1),
        };
        assert_eq!(
            invalid_class
                .validate(CompileLimits::default())
                .expect_err("invalid class")
                .kind,
            CompileErrorKind::InvalidClassReference
        );

        let mut invalid_slot = capture_split_program();
        invalid_slot.states[0].instruction = Instruction::Save {
            slot: CaptureSlot::new(9),
            target: StateId::new(1),
        };
        assert_eq!(
            invalid_slot
                .validate(CompileLimits::default())
                .expect_err("invalid slot")
                .kind,
            CompileErrorKind::InvalidCaptureSlot
        );

        let mut invalid_accept = literal_program();
        invalid_accept.states[1].instruction = Instruction::Jump {
            target: StateId::new(1),
        };
        invalid_accept.resources =
            CompileResources::checked(&invalid_accept.states, &invalid_accept.classes, 0, 0)
                .expect("accounting");
        assert_eq!(
            invalid_accept
                .validate(CompileLimits::default())
                .expect_err("accept must be terminal")
                .kind,
            CompileErrorKind::AcceptNotTerminal
        );
    }

    #[test]
    fn malformed_spans_classes_reachability_and_references_are_rejected() {
        let mut bad_span = literal_program();
        bad_span.states[0].source.byte_end = 0;
        assert_eq!(
            bad_span
                .validate(CompileLimits::default())
                .expect_err("scalar width cannot exceed byte width")
                .kind,
            CompileErrorKind::InvalidSpan
        );

        let mut bad_class = literal_program();
        bad_class.classes[0].ranges = CanonicalRanges::Unicode(vec![ScalarRange::new('z', 'a')]);
        assert_eq!(
            bad_class
                .validate(CompileLimits::default())
                .expect_err("descending class range")
                .kind,
            CompileErrorKind::NonCanonicalClass
        );

        let mut unreachable = literal_program();
        unreachable.states.insert(
            1,
            State {
                instruction: Instruction::Jump {
                    target: StateId::new(2),
                },
                source: EMPTY_SPAN,
            },
        );
        unreachable.accept = StateId::new(2);
        unreachable.states[0].instruction = Instruction::Consume {
            class: ClassId::new(0),
            target: StateId::new(2),
        };
        unreachable.resources =
            CompileResources::checked(&unreachable.states, &unreachable.classes, 0, 0)
                .expect("accounting");
        assert_eq!(
            unreachable
                .validate(CompileLimits::default())
                .expect_err("state 1 is unreachable")
                .kind,
            CompileErrorKind::UnreachableState
        );

        let mut unreferenced = literal_program();
        unreferenced.classes.push(IrClass {
            ranges: CanonicalRanges::Bytes(vec![ByteRange::new(b'0', b'9')]),
            source: ONE_SPAN,
        });
        unreferenced.resources =
            CompileResources::checked(&unreferenced.states, &unreferenced.classes, 0, 0)
                .expect("accounting");
        assert_eq!(
            unreferenced
                .validate(CompileLimits::default())
                .expect_err("unused class")
                .kind,
            CompileErrorKind::UnreferencedClass
        );
    }

    #[test]
    fn every_resource_ceiling_fails_closed() {
        let program = capture_split_program();
        let cases = [
            (
                CompileLimits {
                    max_states: program.resources.states - 1,
                    ..CompileLimits::default()
                },
                CompileErrorKind::StateLimit,
            ),
            (
                CompileLimits {
                    max_transitions: program.resources.transitions - 1,
                    ..CompileLimits::default()
                },
                CompileErrorKind::TransitionLimit,
            ),
            (
                CompileLimits {
                    max_classes: 0,
                    ..CompileLimits::default()
                },
                CompileErrorKind::InvalidLimits,
            ),
            (
                CompileLimits {
                    max_ranges_per_class: 0,
                    ..CompileLimits::default()
                },
                CompileErrorKind::InvalidLimits,
            ),
            (
                CompileLimits {
                    max_total_class_ranges: 0,
                    ..CompileLimits::default()
                },
                CompileErrorKind::InvalidLimits,
            ),
            (
                CompileLimits {
                    max_capture_slots: 1,
                    ..CompileLimits::default()
                },
                CompileErrorKind::CaptureSlotLimit,
            ),
            (
                CompileLimits {
                    max_memory_bytes: program.resources.accounted_memory_bytes - 1,
                    ..CompileLimits::default()
                },
                CompileErrorKind::MemoryLimit,
            ),
            (
                CompileLimits {
                    max_work_units: program.resources.work_units - 1,
                    ..CompileLimits::default()
                },
                CompileErrorKind::WorkLimit,
            ),
        ];
        for (limits, expected) in cases {
            assert_eq!(
                program
                    .validate(limits)
                    .expect_err("ceiling must reject")
                    .kind,
                expected
            );
        }

        let repetition = Program::checked(
            StateId::new(0),
            StateId::new(0),
            vec![State {
                instruction: Instruction::Accept,
                source: EMPTY_SPAN,
            }],
            vec![],
            0,
            2,
            CompileLimits::default(),
        )
        .expect("repetition accounting program");
        assert_eq!(
            repetition
                .validate(CompileLimits {
                    max_repetition_expansion: 1,
                    ..CompileLimits::default()
                })
                .expect_err("repetition ceiling")
                .kind,
            CompileErrorKind::RepetitionLimit
        );
    }

    #[test]
    fn malformed_input_validation_is_panic_free() {
        let mut malformed = capture_split_program();
        malformed.entry = StateId::new(usize::MAX);
        let result = std::panic::catch_unwind(|| malformed.validate(CompileLimits::default()));
        assert!(result.is_ok(), "validator must contain malformed input");
        assert_eq!(
            result
                .expect("panic containment")
                .expect_err("invalid entry must fail")
                .kind,
            CompileErrorKind::InvalidEntry
        );
    }

    #[test]
    fn error_codes_are_unique_and_diagnostics_do_not_echo_patterns() {
        let kinds = [
            CompileErrorKind::InvalidLimits,
            CompileErrorKind::InvalidSchema,
            CompileErrorKind::ArithmeticOverflow,
            CompileErrorKind::EmptyProgram,
            CompileErrorKind::StateLimit,
            CompileErrorKind::TransitionLimit,
            CompileErrorKind::ClassLimit,
            CompileErrorKind::ClassRangeLimit,
            CompileErrorKind::TotalClassRangeLimit,
            CompileErrorKind::CaptureSlotLimit,
            CompileErrorKind::OddCaptureSlots,
            CompileErrorKind::RepetitionLimit,
            CompileErrorKind::MemoryLimit,
            CompileErrorKind::WorkLimit,
            CompileErrorKind::ResourceAccountingMismatch,
            CompileErrorKind::InvalidEntry,
            CompileErrorKind::InvalidAccept,
            CompileErrorKind::AcceptNotTerminal,
            CompileErrorKind::ExtraAcceptState,
            CompileErrorKind::InvalidTarget,
            CompileErrorKind::InvalidClassReference,
            CompileErrorKind::InvalidCaptureSlot,
            CompileErrorKind::InvalidSpan,
            CompileErrorKind::NonCanonicalClass,
            CompileErrorKind::UnreferencedClass,
            CompileErrorKind::UnreferencedCaptureSlot,
            CompileErrorKind::AcceptUnreachable,
            CompileErrorKind::UnreachableState,
        ];
        let mut codes = kinds.map(CompileErrorKind::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));

        let error = CompileError::new(CompileErrorKind::InvalidTarget)
            .with_state(StateId::new(3))
            .with_span(ONE_SPAN);
        let display = error.to_string();
        assert!(display.starts_with("[RGX-IR-E020]"));
        assert!(!display.contains("secret-pattern"));
    }
}
