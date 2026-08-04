//! Checked AST-to-Thompson-IR lowering for the candidate regex compiler.
//!
//! This private R3.3 compiler surface consumes the pinned R3.2 character, fold,
//! and boundary analysis. It lowers structural atoms, ordered alternation,
//! capture boundaries, and bounded or consuming repetition. Nullable
//! unbounded loops and capture-erasing zero repeats fail closed. No incomplete
//! state graph can escape as an executable [`Program`].

use core::fmt;

use super::regex_boundaries::{
    self, BoundaryAssertion, FoldBoundaryAnalysis, FoldBoundaryError, FoldBoundaryErrorKind,
    FoldBoundaryLimits, FoldOutput,
};
use super::regex_ir::{
    ACCOUNTED_PROGRAM_BYTES, CaptureSlot, ClassId, CompileError, CompileErrorKind, CompileLimits,
    Instruction, IrClass, Program, State, StateId,
};
use super::regex_semantics::{CanonicalClass, CanonicalRanges, ScalarRange, SemanticLimits};
use super::regex_syntax::{
    AstNodeKind, Escape, ExpansionBound, Greediness, LexerLimits, NodeId, ParserLimits, Quantifier,
    RepetitionRange, SourceSpan,
};

pub const LOWERING_ID: &str = "ASUP-REGEX-THOMPSON-LOWERING-V1";
pub const LOWERING_SCHEMA_VERSION: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerErrorKind {
    Analysis(FoldBoundaryErrorKind),
    Compile(CompileErrorKind),
    InvalidAnalysis,
    MissingSemanticClass,
    MissingBoundary,
    MissingFragment,
    DuplicatePatch,
    UnresolvedPatch,
    NullableUnboundedRepetition,
    CaptureErasedByZeroRepetition,
    InvalidCaptureIndex,
}

impl LowerErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Analysis(kind) => kind.code(),
            Self::Compile(kind) => kind.code(),
            Self::InvalidAnalysis => "RGX-LOWER-E001",
            Self::MissingSemanticClass => "RGX-LOWER-E002",
            Self::MissingBoundary => "RGX-LOWER-E003",
            Self::MissingFragment => "RGX-LOWER-E004",
            Self::DuplicatePatch => "RGX-LOWER-E005",
            Self::UnresolvedPatch => "RGX-LOWER-E006",
            Self::NullableUnboundedRepetition => "RGX-LOWER-E009",
            Self::CaptureErasedByZeroRepetition => "RGX-LOWER-E010",
            Self::InvalidCaptureIndex => "RGX-LOWER-E011",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowerError {
    pub kind: LowerErrorKind,
    pub span: SourceSpan,
    pub actual: Option<u64>,
    pub limit: Option<u64>,
}

impl LowerError {
    const fn new(kind: LowerErrorKind, span: SourceSpan) -> Self {
        Self {
            kind,
            span,
            actual: None,
            limit: None,
        }
    }

    fn analysis(error: FoldBoundaryError) -> Self {
        Self::new(LowerErrorKind::Analysis(error.kind), error.span)
    }

    fn compile(error: CompileError, fallback_span: SourceSpan) -> Self {
        Self {
            kind: LowerErrorKind::Compile(error.kind),
            span: error.span.unwrap_or(fallback_span),
            actual: error.actual,
            limit: error.limit,
        }
    }

    fn compile_limit<A, L>(kind: CompileErrorKind, span: SourceSpan, actual: A, limit: L) -> Self
    where
        A: TryInto<u64>,
        L: TryInto<u64>,
    {
        Self {
            kind: LowerErrorKind::Compile(kind),
            span,
            actual: actual.try_into().ok(),
            limit: limit.try_into().ok(),
        }
    }

    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for LowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}] {:?} at bytes {}..{} (scalars {}..{})",
            self.code(),
            self.kind,
            self.span.byte_start,
            self.span.byte_end,
            self.span.scalar_start,
            self.span.scalar_end
        )?;
        if let (Some(actual), Some(limit)) = (self.actual, self.limit) {
            write!(formatter, " actual={actual} limit={limit}")?;
        }
        Ok(())
    }
}

impl std::error::Error for LowerError {}

/// Parse, semantically normalize, and lower one pattern into a complete IR.
///
/// The returned value has passed both the R3.2 analysis invariants and
/// [`Program::checked`]. Repetition expansion is bounded before state cloning,
/// and partial graphs never escape when a capture or repetition is rejected.
pub fn lower(
    pattern: &str,
    lexer_limits: LexerLimits,
    parser_limits: ParserLimits,
    semantic_limits: SemanticLimits,
    fold_boundary_limits: FoldBoundaryLimits,
    compile_limits: CompileLimits,
) -> Result<Program, LowerError> {
    let analysis = regex_boundaries::analyze(
        pattern,
        lexer_limits,
        parser_limits,
        semantic_limits,
        fold_boundary_limits,
    )
    .map_err(LowerError::analysis)?;
    let fallback_span = pattern_span(pattern);
    if !analysis.invariants_hold(pattern, semantic_limits, fold_boundary_limits) {
        return Err(LowerError::new(
            LowerErrorKind::InvalidAnalysis,
            fallback_span,
        ));
    }
    if !compile_limits_hold(compile_limits) {
        return Err(LowerError::new(
            LowerErrorKind::Compile(CompileErrorKind::InvalidLimits),
            fallback_span,
        ));
    }
    LoweringBuilder::new(&analysis, compile_limits).run()
}

fn compile_limits_hold(limits: CompileLimits) -> bool {
    limits.max_states > 0
        && limits.max_transitions > 0
        && limits.max_classes > 0
        && limits.max_ranges_per_class > 0
        && limits.max_total_class_ranges > 0
        && limits.max_capture_slots > 0
        && limits.max_repetition_expansion > 0
        && limits.max_memory_bytes >= ACCOUNTED_PROGRAM_BYTES
        && limits.max_work_units > 0
}

fn pattern_span(pattern: &str) -> SourceSpan {
    SourceSpan {
        byte_start: 0,
        byte_end: pattern.len(),
        scalar_start: 0,
        scalar_end: pattern.chars().count(),
    }
}

#[derive(Debug, Clone)]
enum PendingInstruction {
    Accept,
    Jump {
        target: Option<StateId>,
    },
    Split {
        preferred: StateId,
        fallback: StateId,
    },
    Consume {
        class: ClassId,
        target: Option<StateId>,
    },
    Assert {
        kind: regex_boundaries::BoundaryKind,
        target: Option<StateId>,
    },
    Save {
        slot: CaptureSlot,
        target: Option<StateId>,
    },
}

#[derive(Debug)]
struct PendingState {
    instruction: PendingInstruction,
    source: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Patch {
    state: StateId,
}

#[derive(Debug)]
struct Fragment {
    start: StateId,
    outs: Vec<Patch>,
}

struct LoweringBuilder<'analysis> {
    analysis: &'analysis FoldBoundaryAnalysis,
    limits: CompileLimits,
    states: Vec<PendingState>,
    classes: Vec<IrClass>,
    fragments: Vec<Option<Fragment>>,
    semantic_classes_used: Vec<bool>,
    folds_used: Vec<bool>,
    boundaries_used: Vec<bool>,
    total_class_ranges: usize,
    capture_slots: usize,
    repetition_expansion: u64,
}

impl<'analysis> LoweringBuilder<'analysis> {
    fn new(analysis: &'analysis FoldBoundaryAnalysis, limits: CompileLimits) -> Self {
        Self {
            analysis,
            limits,
            states: Vec::new(),
            classes: Vec::new(),
            fragments: Vec::new(),
            semantic_classes_used: vec![false; analysis.character_semantics.classes.len()],
            folds_used: vec![false; analysis.folds.len()],
            boundaries_used: vec![false; analysis.boundaries.len()],
            total_class_ranges: 0,
            capture_slots: 0,
            repetition_expansion: 0,
        }
    }

    fn run(mut self) -> Result<Program, LowerError> {
        let ast = &self.analysis.character_semantics.ast;
        let root_span = ast
            .node(ast.root)
            .map_or_else(|| pattern_span(""), |node| node.span);
        for index in 0..ast.nodes.len() {
            let node = &ast.nodes[index];
            let kind = node.kind.clone();
            let fragment = self.lower_node(kind, node.span)?;
            if self.fragments.len() != index {
                return Err(LowerError::new(LowerErrorKind::InvalidAnalysis, node.span));
            }
            self.fragments.push(fragment);
        }

        let root = self.take_fragment(ast.root, root_span)?;
        self.ensure_analysis_consumed()?;
        let accept_span = SourceSpan {
            byte_start: root_span.byte_end,
            byte_end: root_span.byte_end,
            scalar_start: root_span.scalar_end,
            scalar_end: root_span.scalar_end,
        };
        let accept = self.push_state(PendingInstruction::Accept, accept_span)?;
        self.patch(&root.outs, accept, root_span)?;
        let (entry, accept) = self.prune_pending_unreachable(root.start, accept, root_span)?;
        let states = self.finish_states()?;
        Program::checked(
            entry,
            accept,
            states,
            self.classes,
            self.capture_slots,
            self.repetition_expansion,
            self.limits,
        )
        .map_err(|error| LowerError::compile(error, root_span))
    }

    fn lower_node(
        &mut self,
        kind: AstNodeKind,
        span: SourceSpan,
    ) -> Result<Option<Fragment>, LowerError> {
        match kind {
            AstNodeKind::Empty => self.empty_fragment(span).map(Some),
            AstNodeKind::Literal(value) => self.literal_fragment(value, span).map(Some),
            AstNodeKind::Dot => self.semantic_class_fragment(span).map(Some),
            AstNodeKind::Escape(escape) => self.escape_fragment(escape, span).map(Some),
            AstNodeKind::Assertion(_) | AstNodeKind::LineStart | AstNodeKind::LineEnd => {
                self.assertion_fragment(span).map(Some)
            }
            AstNodeKind::Concat(children) => self.concat_children(&children, span).map(Some),
            AstNodeKind::Alternation(children) => {
                self.alternate_children(&children, span).map(Some)
            }
            AstNodeKind::NonCapturing { child } => self.take_fragment(child, span).map(Some),
            AstNodeKind::Flags {
                child: Some(child), ..
            } => self.take_fragment(child, span).map(Some),
            AstNodeKind::Flags { child: None, .. } => self.empty_fragment(span).map(Some),
            AstNodeKind::Capture { index, child, .. } => {
                self.capture_fragment(index, child, span).map(Some)
            }
            AstNodeKind::Repetition {
                child,
                quantifier,
                greediness,
            } => self
                .repetition_fragment(child, quantifier, greediness, span)
                .map(Some),
            AstNodeKind::Class { .. } => self.semantic_class_fragment(span).map(Some),
            AstNodeKind::ClassLiteral(_)
            | AstNodeKind::ClassEscape(_)
            | AstNodeKind::PosixClass { .. }
            | AstNodeKind::ClassRange { .. }
            | AstNodeKind::ClassUnion(_)
            | AstNodeKind::ClassSet { .. } => Ok(None),
        }
    }

    fn literal_fragment(&mut self, value: char, span: SourceSpan) -> Result<Fragment, LowerError> {
        if let Some(output) = self.take_fold_output(span)? {
            self.output_fragment(output, span)
        } else {
            self.class_fragment(
                CanonicalRanges::Unicode(vec![ScalarRange::new(value, value)]),
                span,
            )
        }
    }

    fn escape_fragment(
        &mut self,
        escape: Escape,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        match escape {
            Escape::Literal(value)
            | Escape::Control(value)
            | Escape::Hex(value)
            | Escape::Unicode(value) => self.literal_fragment(value, span),
            Escape::PerlClass(_) | Escape::UnicodeClass { .. } => {
                self.semantic_class_fragment(span)
            }
            Escape::Assertion(_) => self.assertion_fragment(span),
        }
    }

    fn semantic_class_fragment(&mut self, span: SourceSpan) -> Result<Fragment, LowerError> {
        let semantic_ranges = self.take_semantic_class(span)?.ranges;
        if let Some(output) = self.take_fold_output(span)? {
            self.output_fragment(output, span)
        } else {
            self.class_fragment(semantic_ranges, span)
        }
    }

    fn assertion_fragment(&mut self, span: SourceSpan) -> Result<Fragment, LowerError> {
        let boundary = self.take_boundary(span)?;
        let state = self.push_state(
            PendingInstruction::Assert {
                kind: boundary.kind,
                target: None,
            },
            span,
        )?;
        Ok(Fragment {
            start: state,
            outs: vec![Patch { state }],
        })
    }

    fn output_fragment(
        &mut self,
        output: FoldOutput,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        match output {
            FoldOutput::Ranges(ranges) => self.class_fragment(ranges, span),
            FoldOutput::ExactBytes(bytes) => {
                let mut fragments = Vec::with_capacity(bytes.len());
                for byte in bytes {
                    fragments.push(self.class_fragment(
                        CanonicalRanges::Bytes(vec![super::regex_semantics::ByteRange::new(
                            byte, byte,
                        )]),
                        span,
                    )?);
                }
                self.concat_fragments(fragments, span)
            }
        }
    }

    fn class_fragment(
        &mut self,
        ranges: CanonicalRanges,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let class = self.push_class(ranges, span)?;
        let state = self.push_state(
            PendingInstruction::Consume {
                class,
                target: None,
            },
            span,
        )?;
        Ok(Fragment {
            start: state,
            outs: vec![Patch { state }],
        })
    }

    fn empty_fragment(&mut self, span: SourceSpan) -> Result<Fragment, LowerError> {
        let state = self.push_state(PendingInstruction::Jump { target: None }, span)?;
        Ok(Fragment {
            start: state,
            outs: vec![Patch { state }],
        })
    }

    fn capture_fragment(
        &mut self,
        index: usize,
        child: NodeId,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let Some(slot_start) = index.checked_sub(1).and_then(|value| value.checked_mul(2)) else {
            return Err(LowerError::new(LowerErrorKind::InvalidCaptureIndex, span));
        };
        let Some(slot_end) = slot_start.checked_add(1) else {
            return Err(LowerError::new(LowerErrorKind::InvalidCaptureIndex, span));
        };
        let Some(required_slots) = slot_end.checked_add(1) else {
            return Err(LowerError::new(LowerErrorKind::InvalidCaptureIndex, span));
        };
        if required_slots > self.limits.max_capture_slots {
            return Err(LowerError::compile_limit(
                CompileErrorKind::CaptureSlotLimit,
                span,
                required_slots,
                self.limits.max_capture_slots,
            ));
        }

        let child = self.take_fragment(child, span)?;
        let end_span = zero_width_span(span.byte_end, span.scalar_end);
        let end = self.push_state(
            PendingInstruction::Save {
                slot: CaptureSlot::new(slot_end),
                target: None,
            },
            end_span,
        )?;
        self.patch(&child.outs, end, span)?;
        let start_span = zero_width_span(span.byte_start, span.scalar_start);
        let start = self.push_state(
            PendingInstruction::Save {
                slot: CaptureSlot::new(slot_start),
                target: Some(child.start),
            },
            start_span,
        )?;
        self.capture_slots = self.capture_slots.max(required_slots);
        Ok(Fragment {
            start,
            outs: vec![Patch { state: end }],
        })
    }

    fn repetition_fragment(
        &mut self,
        child: NodeId,
        quantifier: Quantifier,
        greediness: Greediness,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let child_is_nullable = self
            .analysis
            .character_semantics
            .ast
            .node(child)
            .is_some_and(|node| matches!(node.expansion.minimum, ExpansionBound::Finite(0)));
        let child = self.take_fragment(child, span)?;

        match quantifier {
            Quantifier::ZeroOrOne => self.optional_fragment(child, greediness, span),
            Quantifier::ZeroOrMore => {
                if child_is_nullable {
                    return Err(LowerError::new(
                        LowerErrorKind::NullableUnboundedRepetition,
                        span,
                    ));
                }
                self.zero_or_more_fragment(child, greediness, span)
            }
            Quantifier::OneOrMore => {
                if child_is_nullable {
                    return Err(LowerError::new(
                        LowerErrorKind::NullableUnboundedRepetition,
                        span,
                    ));
                }
                self.one_or_more_fragment(child, greediness, span)
            }
            Quantifier::Counted(RepetitionRange::Exact(count)) => {
                self.exact_repetition_fragment(child, count, span)
            }
            Quantifier::Counted(RepetitionRange::AtLeast(minimum)) => {
                if child_is_nullable {
                    return Err(LowerError::new(
                        LowerErrorKind::NullableUnboundedRepetition,
                        span,
                    ));
                }
                self.at_least_fragment(child, minimum, greediness, span)
            }
            Quantifier::Counted(RepetitionRange::Bounded { min, max }) => {
                self.bounded_repetition_fragment(child, min, max, greediness, span)
            }
        }
    }

    fn optional_fragment(
        &mut self,
        child: Fragment,
        greediness: Greediness,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let empty = self.empty_fragment(span)?;
        self.ordered_choice(child, empty, greediness, span)
    }

    fn zero_or_more_fragment(
        &mut self,
        child: Fragment,
        greediness: Greediness,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let exit = self.empty_fragment(span)?;
        let (preferred, fallback) = match greediness {
            Greediness::Greedy => (child.start, exit.start),
            Greediness::Lazy => (exit.start, child.start),
        };
        let split = self.push_state(
            PendingInstruction::Split {
                preferred,
                fallback,
            },
            span,
        )?;
        self.patch(&child.outs, split, span)?;
        Ok(Fragment {
            start: split,
            outs: exit.outs,
        })
    }

    fn one_or_more_fragment(
        &mut self,
        child: Fragment,
        greediness: Greediness,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let exit = self.empty_fragment(span)?;
        let (preferred, fallback) = match greediness {
            Greediness::Greedy => (child.start, exit.start),
            Greediness::Lazy => (exit.start, child.start),
        };
        let split = self.push_state(
            PendingInstruction::Split {
                preferred,
                fallback,
            },
            span,
        )?;
        self.patch(&child.outs, split, span)?;
        Ok(Fragment {
            start: child.start,
            outs: exit.outs,
        })
    }

    fn exact_repetition_fragment(
        &mut self,
        child: Fragment,
        count: u32,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        if count == 0 {
            if self.fragment_contains_save(&child)? {
                return Err(LowerError::new(
                    LowerErrorKind::CaptureErasedByZeroRepetition,
                    span,
                ));
            }
            return self.empty_fragment(span);
        }

        let additional = usize::try_from(count - 1).map_err(|_| {
            LowerError::compile_limit(
                CompileErrorKind::RepetitionLimit,
                span,
                u64::MAX,
                self.limits.max_repetition_expansion,
            )
        })?;
        let copies = self.clone_copies(&child, additional, span)?;
        let mut fragments = Vec::with_capacity(copies.len().saturating_add(1));
        fragments.push(Fragment {
            start: child.start,
            outs: child.outs.clone(),
        });
        fragments.extend(copies);
        self.concat_fragments(fragments, span)
    }

    fn at_least_fragment(
        &mut self,
        child: Fragment,
        minimum: u32,
        greediness: Greediness,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        if minimum == 0 {
            return self.zero_or_more_fragment(child, greediness, span);
        }

        let additional = usize::try_from(minimum - 1).map_err(|_| {
            LowerError::compile_limit(
                CompileErrorKind::RepetitionLimit,
                span,
                u64::MAX,
                self.limits.max_repetition_expansion,
            )
        })?;
        let copies = self.clone_copies(&child, additional, span)?;
        let mut fragments = Vec::with_capacity(copies.len().saturating_add(1));
        fragments.push(Fragment {
            start: child.start,
            outs: child.outs.clone(),
        });
        fragments.extend(copies);
        let last = fragments
            .pop()
            .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))?;
        let tail = self.one_or_more_fragment(last, greediness, span)?;
        fragments.push(tail);
        self.concat_fragments(fragments, span)
    }

    fn bounded_repetition_fragment(
        &mut self,
        child: Fragment,
        min: u32,
        max: u32,
        greediness: Greediness,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        if max == 0 {
            if self.fragment_contains_save(&child)? {
                return Err(LowerError::new(
                    LowerErrorKind::CaptureErasedByZeroRepetition,
                    span,
                ));
            }
            return self.empty_fragment(span);
        }

        let additional = usize::try_from(max - 1).map_err(|_| {
            LowerError::compile_limit(
                CompileErrorKind::RepetitionLimit,
                span,
                u64::MAX,
                self.limits.max_repetition_expansion,
            )
        })?;
        let cloned = self.clone_copies(&child, additional, span)?;
        let mut copies = Vec::with_capacity(cloned.len().saturating_add(1));
        copies.push(Fragment {
            start: child.start,
            outs: child.outs.clone(),
        });
        copies.extend(cloned);

        let minimum = usize::try_from(min)
            .map_err(|_| LowerError::new(LowerErrorKind::InvalidAnalysis, span))?;
        let mut optional_tail = self.empty_fragment(span)?;
        while copies.len() > minimum {
            let copy = copies
                .pop()
                .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))?;
            self.patch(&copy.outs, optional_tail.start, span)?;
            let (preferred, fallback) = match greediness {
                Greediness::Greedy => (copy.start, optional_tail.start),
                Greediness::Lazy => (optional_tail.start, copy.start),
            };
            let split = self.push_state(
                PendingInstruction::Split {
                    preferred,
                    fallback,
                },
                span,
            )?;
            optional_tail.start = split;
        }
        copies.push(optional_tail);
        self.concat_fragments(copies, span)
    }

    fn ordered_choice(
        &mut self,
        child: Fragment,
        empty: Fragment,
        greediness: Greediness,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let (preferred, fallback) = match greediness {
            Greediness::Greedy => (child.start, empty.start),
            Greediness::Lazy => (empty.start, child.start),
        };
        let split = self.push_state(
            PendingInstruction::Split {
                preferred,
                fallback,
            },
            span,
        )?;
        let mut outs = child.outs;
        outs.extend(empty.outs);
        Ok(Fragment { start: split, outs })
    }

    fn concat_children(
        &mut self,
        children: &[NodeId],
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let mut fragments = Vec::with_capacity(children.len());
        for child in children {
            fragments.push(self.take_fragment(*child, span)?);
        }
        self.concat_fragments(fragments, span)
    }

    fn concat_fragments(
        &mut self,
        fragments: Vec<Fragment>,
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let mut fragments = fragments.into_iter();
        let Some(mut combined) = fragments.next() else {
            return self.empty_fragment(span);
        };
        for next in fragments {
            self.patch(&combined.outs, next.start, span)?;
            combined.outs = next.outs;
        }
        Ok(combined)
    }

    fn alternate_children(
        &mut self,
        children: &[NodeId],
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let mut fragments = Vec::with_capacity(children.len());
        for child in children {
            fragments.push(self.take_fragment(*child, span)?);
        }
        let Some(mut combined) = fragments.pop() else {
            return self.empty_fragment(span);
        };
        while let Some(preferred) = fragments.pop() {
            let split = self.push_state(
                PendingInstruction::Split {
                    preferred: preferred.start,
                    fallback: combined.start,
                },
                span,
            )?;
            let mut outs = preferred.outs;
            outs.extend(combined.outs);
            combined = Fragment { start: split, outs };
        }
        Ok(combined)
    }

    fn clone_copies(
        &mut self,
        fragment: &Fragment,
        count: usize,
        span: SourceSpan,
    ) -> Result<Vec<Fragment>, LowerError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let state_ids = self.fragment_state_ids(fragment, span)?;
        let added = state_ids.len().checked_mul(count).ok_or_else(|| {
            LowerError::compile_limit(
                CompileErrorKind::RepetitionLimit,
                span,
                u64::MAX,
                self.limits.max_repetition_expansion,
            )
        })?;
        let added_u64 = u64::try_from(added).map_err(|_| {
            LowerError::compile_limit(
                CompileErrorKind::RepetitionLimit,
                span,
                u64::MAX,
                self.limits.max_repetition_expansion,
            )
        })?;
        let next_expansion = self
            .repetition_expansion
            .checked_add(added_u64)
            .ok_or_else(|| {
                LowerError::compile_limit(
                    CompileErrorKind::RepetitionLimit,
                    span,
                    u64::MAX,
                    self.limits.max_repetition_expansion,
                )
            })?;
        if next_expansion > self.limits.max_repetition_expansion {
            return Err(LowerError::compile_limit(
                CompileErrorKind::RepetitionLimit,
                span,
                next_expansion,
                self.limits.max_repetition_expansion,
            ));
        }
        let next_states = self.states.len().checked_add(added).ok_or_else(|| {
            LowerError::compile_limit(
                CompileErrorKind::StateLimit,
                span,
                u64::MAX,
                self.limits.max_states,
            )
        })?;
        if next_states > self.limits.max_states {
            return Err(LowerError::compile_limit(
                CompileErrorKind::StateLimit,
                span,
                next_states,
                self.limits.max_states,
            ));
        }

        self.repetition_expansion = next_expansion;
        let mut copies = Vec::with_capacity(count);
        for _ in 0..count {
            copies.push(self.clone_fragment(fragment, &state_ids, span)?);
        }
        Ok(copies)
    }

    fn clone_fragment(
        &mut self,
        fragment: &Fragment,
        state_ids: &[StateId],
        span: SourceSpan,
    ) -> Result<Fragment, LowerError> {
        let original_count = self.states.len();
        let mut remap = vec![None; original_count];
        for state_id in state_ids {
            let source = self
                .states
                .get(state_id.index())
                .map(|state| state.source)
                .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))?;
            let clone_id = self.push_state(PendingInstruction::Accept, source)?;
            remap[state_id.index()] = Some(clone_id);
        }

        for state_id in state_ids {
            let instruction = self
                .states
                .get(state_id.index())
                .map(|state| state.instruction.clone())
                .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))?;
            let translated = translate_pending(instruction, &remap, span)?;
            let clone_id = remap[state_id.index()]
                .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))?;
            let clone_state = self
                .states
                .get_mut(clone_id.index())
                .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))?;
            clone_state.instruction = translated;
        }

        let start = remap
            .get(fragment.start.index())
            .and_then(|entry| *entry)
            .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))?;
        let mut outs = Vec::with_capacity(fragment.outs.len());
        for patch in &fragment.outs {
            let state = remap
                .get(patch.state.index())
                .and_then(|entry| *entry)
                .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))?;
            outs.push(Patch { state });
        }
        Ok(Fragment { start, outs })
    }

    fn fragment_state_ids(
        &self,
        fragment: &Fragment,
        span: SourceSpan,
    ) -> Result<Vec<StateId>, LowerError> {
        let mut visited = vec![false; self.states.len()];
        let mut pending = vec![fragment.start];
        let mut state_ids = Vec::new();
        while let Some(state_id) = pending.pop() {
            let Some(visited_state) = visited.get_mut(state_id.index()) else {
                return Err(LowerError::new(LowerErrorKind::MissingFragment, span));
            };
            if *visited_state {
                continue;
            }
            *visited_state = true;
            let state = self
                .states
                .get(state_id.index())
                .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))?;
            state_ids.push(state_id);
            pending.extend(pending_targets(&state.instruction));
        }
        state_ids.sort_unstable_by_key(|state_id| state_id.index());
        Ok(state_ids)
    }

    fn fragment_contains_save(&self, fragment: &Fragment) -> Result<bool, LowerError> {
        let state_ids = self.fragment_state_ids(
            fragment,
            self.states
                .get(fragment.start.index())
                .map_or_else(|| pattern_span(""), |state| state.source),
        )?;
        Ok(state_ids.iter().any(|state_id| {
            self.states
                .get(state_id.index())
                .is_some_and(|state| matches!(state.instruction, PendingInstruction::Save { .. }))
        }))
    }

    fn take_fragment(&mut self, id: NodeId, span: SourceSpan) -> Result<Fragment, LowerError> {
        self.fragments
            .get_mut(id.index())
            .and_then(Option::take)
            .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))
    }

    fn push_state(
        &mut self,
        instruction: PendingInstruction,
        source: SourceSpan,
    ) -> Result<StateId, LowerError> {
        let next = self.states.len().checked_add(1).ok_or_else(|| {
            LowerError::compile_limit(
                CompileErrorKind::StateLimit,
                source,
                u64::MAX,
                self.limits.max_states,
            )
        })?;
        if next > self.limits.max_states {
            return Err(LowerError::compile_limit(
                CompileErrorKind::StateLimit,
                source,
                next,
                self.limits.max_states,
            ));
        }
        let id = StateId::new(self.states.len());
        self.states.push(PendingState {
            instruction,
            source,
        });
        Ok(id)
    }

    fn push_class(
        &mut self,
        ranges: CanonicalRanges,
        source: SourceSpan,
    ) -> Result<ClassId, LowerError> {
        let next = self.classes.len().checked_add(1).ok_or_else(|| {
            LowerError::compile_limit(
                CompileErrorKind::ClassLimit,
                source,
                u64::MAX,
                self.limits.max_classes,
            )
        })?;
        if next > self.limits.max_classes {
            return Err(LowerError::compile_limit(
                CompileErrorKind::ClassLimit,
                source,
                next,
                self.limits.max_classes,
            ));
        }
        let range_count = ranges.range_count();
        if range_count > self.limits.max_ranges_per_class {
            return Err(LowerError::compile_limit(
                CompileErrorKind::ClassRangeLimit,
                source,
                range_count,
                self.limits.max_ranges_per_class,
            ));
        }
        let Some(total) = self.total_class_ranges.checked_add(range_count) else {
            return Err(LowerError::compile_limit(
                CompileErrorKind::TotalClassRangeLimit,
                source,
                u64::MAX,
                self.limits.max_total_class_ranges,
            ));
        };
        if total > self.limits.max_total_class_ranges {
            return Err(LowerError::compile_limit(
                CompileErrorKind::TotalClassRangeLimit,
                source,
                total,
                self.limits.max_total_class_ranges,
            ));
        }
        let id = ClassId::new(self.classes.len());
        self.classes.push(IrClass { ranges, source });
        self.total_class_ranges = total;
        Ok(id)
    }

    fn patch(
        &mut self,
        patches: &[Patch],
        target: StateId,
        span: SourceSpan,
    ) -> Result<(), LowerError> {
        for patch in patches {
            let Some(state) = self.states.get_mut(patch.state.index()) else {
                return Err(LowerError::new(LowerErrorKind::MissingFragment, span));
            };
            let slot = match &mut state.instruction {
                PendingInstruction::Jump { target }
                | PendingInstruction::Consume { target, .. }
                | PendingInstruction::Assert { target, .. }
                | PendingInstruction::Save { target, .. } => target,
                PendingInstruction::Accept | PendingInstruction::Split { .. } => {
                    return Err(LowerError::new(LowerErrorKind::DuplicatePatch, span));
                }
            };
            if slot.replace(target).is_some() {
                return Err(LowerError::new(LowerErrorKind::DuplicatePatch, span));
            }
        }
        Ok(())
    }

    fn take_semantic_class(&mut self, span: SourceSpan) -> Result<CanonicalClass, LowerError> {
        let index = unique_unused_span(
            &self.analysis.character_semantics.classes,
            &self.semantic_classes_used,
            span,
            |class| class.span,
        )
        .ok_or_else(|| LowerError::new(LowerErrorKind::MissingSemanticClass, span))??;
        self.semantic_classes_used[index] = true;
        Ok(self.analysis.character_semantics.classes[index].clone())
    }

    fn take_fold_output(&mut self, span: SourceSpan) -> Result<Option<FoldOutput>, LowerError> {
        let Some(index) =
            unique_unused_span(&self.analysis.folds, &self.folds_used, span, |fold| {
                fold.span
            })
        else {
            return Ok(None);
        };
        let index = index?;
        self.folds_used[index] = true;
        Ok(Some(self.analysis.folds[index].folded.clone()))
    }

    fn take_boundary(&mut self, span: SourceSpan) -> Result<BoundaryAssertion, LowerError> {
        let index = unique_unused_span(
            &self.analysis.boundaries,
            &self.boundaries_used,
            span,
            |boundary| boundary.span,
        )
        .ok_or_else(|| LowerError::new(LowerErrorKind::MissingBoundary, span))??;
        self.boundaries_used[index] = true;
        Ok(self.analysis.boundaries[index])
    }

    fn ensure_analysis_consumed(&self) -> Result<(), LowerError> {
        if let Some(index) = self.semantic_classes_used.iter().position(|used| !used) {
            return Err(LowerError::new(
                LowerErrorKind::MissingSemanticClass,
                self.analysis.character_semantics.classes[index].span,
            ));
        }
        if let Some(index) = self.folds_used.iter().position(|used| !used) {
            return Err(LowerError::new(
                LowerErrorKind::InvalidAnalysis,
                self.analysis.folds[index].span,
            ));
        }
        if let Some(index) = self.boundaries_used.iter().position(|used| !used) {
            return Err(LowerError::new(
                LowerErrorKind::MissingBoundary,
                self.analysis.boundaries[index].span,
            ));
        }
        Ok(())
    }

    fn prune_pending_unreachable(
        &mut self,
        entry: StateId,
        accept: StateId,
        span: SourceSpan,
    ) -> Result<(StateId, StateId), LowerError> {
        let mut reachable = vec![false; self.states.len()];
        let mut pending = vec![entry];
        while let Some(state_id) = pending.pop() {
            let Some(visited) = reachable.get_mut(state_id.index()) else {
                return Err(LowerError::new(LowerErrorKind::InvalidAnalysis, span));
            };
            if *visited {
                continue;
            }
            *visited = true;
            let state = self
                .states
                .get(state_id.index())
                .ok_or_else(|| LowerError::new(LowerErrorKind::InvalidAnalysis, span))?;
            pending.extend(pending_targets(&state.instruction));
        }
        if !reachable.get(accept.index()).copied().unwrap_or(false) {
            return Err(LowerError::new(LowerErrorKind::InvalidAnalysis, span));
        }

        let mut state_remap = vec![None; self.states.len()];
        let mut next_state = 0;
        for (index, is_reachable) in reachable.iter().copied().enumerate() {
            if is_reachable {
                state_remap[index] = Some(StateId::new(next_state));
                next_state += 1;
            }
        }

        let mut referenced_classes = vec![false; self.classes.len()];
        for (index, is_reachable) in reachable.iter().copied().enumerate() {
            if !is_reachable {
                continue;
            }
            if let PendingInstruction::Consume { class, .. } = &self.states[index].instruction {
                let Some(referenced) = referenced_classes.get_mut(class.index()) else {
                    return Err(LowerError::new(LowerErrorKind::InvalidAnalysis, span));
                };
                *referenced = true;
            }
        }
        let mut class_remap = vec![None; self.classes.len()];
        let mut retained_classes = Vec::new();
        for (index, referenced) in referenced_classes.into_iter().enumerate() {
            if referenced {
                class_remap[index] = Some(ClassId::new(retained_classes.len()));
                retained_classes.push(self.classes[index].clone());
            }
        }

        let states = core::mem::take(&mut self.states);
        let mut retained_states = Vec::with_capacity(next_state);
        for (index, state) in states.into_iter().enumerate() {
            if !reachable[index] {
                continue;
            }
            let mut instruction = translate_pending(state.instruction, &state_remap, span)?;
            if let PendingInstruction::Consume { class, .. } = &mut instruction {
                *class = class_remap
                    .get(class.index())
                    .and_then(|mapped| *mapped)
                    .ok_or_else(|| LowerError::new(LowerErrorKind::InvalidAnalysis, span))?;
            }
            retained_states.push(PendingState {
                instruction,
                source: state.source,
            });
        }
        self.states = retained_states;
        self.classes = retained_classes;
        self.total_class_ranges = self
            .classes
            .iter()
            .try_fold(0_usize, |total, class| {
                total.checked_add(class.ranges.range_count())
            })
            .ok_or_else(|| LowerError::new(LowerErrorKind::InvalidAnalysis, span))?;

        let entry = state_remap
            .get(entry.index())
            .and_then(|mapped| *mapped)
            .ok_or_else(|| LowerError::new(LowerErrorKind::InvalidAnalysis, span))?;
        let accept = state_remap
            .get(accept.index())
            .and_then(|mapped| *mapped)
            .ok_or_else(|| LowerError::new(LowerErrorKind::InvalidAnalysis, span))?;
        Ok((entry, accept))
    }

    fn finish_states(&mut self) -> Result<Vec<State>, LowerError> {
        core::mem::take(&mut self.states)
            .into_iter()
            .map(|state| {
                let instruction = match state.instruction {
                    PendingInstruction::Accept => Instruction::Accept,
                    PendingInstruction::Jump { target } => Instruction::Jump {
                        target: target.ok_or_else(|| {
                            LowerError::new(LowerErrorKind::UnresolvedPatch, state.source)
                        })?,
                    },
                    PendingInstruction::Split {
                        preferred,
                        fallback,
                    } => Instruction::Split {
                        preferred,
                        fallback,
                    },
                    PendingInstruction::Consume { class, target } => Instruction::Consume {
                        class,
                        target: target.ok_or_else(|| {
                            LowerError::new(LowerErrorKind::UnresolvedPatch, state.source)
                        })?,
                    },
                    PendingInstruction::Assert { kind, target } => Instruction::Assert {
                        kind,
                        target: target.ok_or_else(|| {
                            LowerError::new(LowerErrorKind::UnresolvedPatch, state.source)
                        })?,
                    },
                    PendingInstruction::Save { slot, target } => Instruction::Save {
                        slot,
                        target: target.ok_or_else(|| {
                            LowerError::new(LowerErrorKind::UnresolvedPatch, state.source)
                        })?,
                    },
                };
                Ok(State {
                    instruction,
                    source: state.source,
                })
            })
            .collect()
    }
}

fn zero_width_span(byte: usize, scalar: usize) -> SourceSpan {
    SourceSpan {
        byte_start: byte,
        byte_end: byte,
        scalar_start: scalar,
        scalar_end: scalar,
    }
}

fn pending_targets(instruction: &PendingInstruction) -> Vec<StateId> {
    match instruction {
        PendingInstruction::Accept => Vec::new(),
        PendingInstruction::Jump {
            target: Some(target),
        }
        | PendingInstruction::Consume {
            target: Some(target),
            ..
        }
        | PendingInstruction::Assert {
            target: Some(target),
            ..
        }
        | PendingInstruction::Save {
            target: Some(target),
            ..
        } => vec![*target],
        PendingInstruction::Jump { target: None }
        | PendingInstruction::Consume { target: None, .. }
        | PendingInstruction::Assert { target: None, .. }
        | PendingInstruction::Save { target: None, .. } => Vec::new(),
        PendingInstruction::Split {
            preferred,
            fallback,
        } => vec![*preferred, *fallback],
    }
}

fn translate_pending(
    instruction: PendingInstruction,
    remap: &[Option<StateId>],
    span: SourceSpan,
) -> Result<PendingInstruction, LowerError> {
    let map = |target: StateId| {
        remap
            .get(target.index())
            .and_then(|entry| *entry)
            .ok_or_else(|| LowerError::new(LowerErrorKind::MissingFragment, span))
    };
    let map_optional = |target: Option<StateId>| target.map(&map).transpose();
    match instruction {
        PendingInstruction::Accept => Ok(PendingInstruction::Accept),
        PendingInstruction::Jump { target } => Ok(PendingInstruction::Jump {
            target: map_optional(target)?,
        }),
        PendingInstruction::Split {
            preferred,
            fallback,
        } => Ok(PendingInstruction::Split {
            preferred: map(preferred)?,
            fallback: map(fallback)?,
        }),
        PendingInstruction::Consume { class, target } => Ok(PendingInstruction::Consume {
            class,
            target: map_optional(target)?,
        }),
        PendingInstruction::Assert { kind, target } => Ok(PendingInstruction::Assert {
            kind,
            target: map_optional(target)?,
        }),
        PendingInstruction::Save { slot, target } => Ok(PendingInstruction::Save {
            slot,
            target: map_optional(target)?,
        }),
    }
}

fn unique_unused_span<T, F>(
    values: &[T],
    used: &[bool],
    span: SourceSpan,
    span_of: F,
) -> Option<Result<usize, LowerError>>
where
    F: Fn(&T) -> SourceSpan,
{
    let mut found = None;
    for (index, value) in values.iter().enumerate() {
        if !used.get(index).copied().unwrap_or(true) && span_of(value) == span {
            if found.is_some() {
                return Some(Err(LowerError::new(LowerErrorKind::InvalidAnalysis, span)));
            }
            found = Some(index);
        }
    }
    found.map(Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower_default(pattern: &str) -> Result<Program, LowerError> {
        lower(
            pattern,
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits::default(),
        )
    }

    #[test]
    fn empty_literal_concat_and_classes_lower_to_checked_programs() {
        let empty = lower_default("").expect("empty expression");
        assert_eq!(empty.resources.states, 2);
        assert!(matches!(
            empty.states[empty.entry.index()].instruction,
            Instruction::Jump { target } if target == empty.accept
        ));

        let concat = lower_default(r"a[0-9]\p{Greek}.").expect("supported atoms");
        concat
            .validate(CompileLimits::default())
            .expect("lowered program validates");
        assert_eq!(concat.resources.states, 5);
        assert_eq!(concat.resources.classes, 4);
        assert!(
            concat
                .classes
                .iter()
                .all(|class| class.ranges.is_canonical())
        );
    }

    #[test]
    fn ordered_alternation_preserves_left_to_right_priority_and_empty_branches() {
        let program = lower_default("a|b|").expect("ordered alternation");
        let Instruction::Split {
            preferred,
            fallback,
        } = program.states[program.entry.index()].instruction
        else {
            panic!("entry must be the left-priority split");
        };
        assert!(matches!(
            program.states[preferred.index()].instruction,
            Instruction::Consume { class, .. }
                if program.classes[class.index()].ranges.contains_scalar('a')
        ));
        let Instruction::Split {
            preferred,
            fallback: final_fallback,
        } = program.states[fallback.index()].instruction
        else {
            panic!("fallback must retain the remaining branch order");
        };
        assert!(matches!(
            program.states[preferred.index()].instruction,
            Instruction::Consume { class, .. }
                if program.classes[class.index()].ranges.contains_scalar('b')
        ));
        assert!(matches!(
            program.states[final_fallback.index()].instruction,
            Instruction::Jump { .. }
        ));
    }

    #[test]
    fn folded_classes_exact_utf8_bytes_and_boundaries_use_r3_2_outputs() {
        let program = lower_default(r"(?i:[a-z])(?i-u:é)\A\b$").expect("fold and boundary outputs");
        assert_eq!(program.resources.classes, 3);
        assert_eq!(
            program
                .classes
                .iter()
                .filter(|class| matches!(class.ranges, CanonicalRanges::Bytes(_)))
                .count(),
            2,
            "the validated non-ASCII byte literal becomes its exact UTF-8 chain"
        );
        assert_eq!(
            program
                .states
                .iter()
                .filter(|state| matches!(state.instruction, Instruction::Assert { .. }))
                .count(),
            3
        );
    }

    #[test]
    fn deep_non_capturing_structure_is_iterative_and_deterministic() {
        let depth = 200;
        let pattern = format!("{}x{}", "(?:".repeat(depth), ")".repeat(depth));
        let parser_limits = ParserLimits {
            max_ast_nodes: 1_024,
            max_nesting: depth + 1,
        };
        let first = lower(
            &pattern,
            LexerLimits::default(),
            parser_limits,
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits::default(),
        )
        .expect("bounded deep pattern");
        let second = lower(
            &pattern,
            LexerLimits::default(),
            parser_limits,
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits::default(),
        )
        .expect("deterministic replay");
        assert_eq!(first, second);
        assert_eq!(first.resources.states, 2);
    }

    #[test]
    fn analysis_and_budget_failures_are_typed_span_aware_and_return_no_program() {
        let syntax = lower_default("(").expect_err("malformed pattern");
        assert!(matches!(
            syntax.kind,
            LowerErrorKind::Analysis(FoldBoundaryErrorKind::CharacterSemantics(_))
        ));
        assert_eq!(syntax.span.byte_start, 0);

        let budget = lower(
            "ab",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits {
                max_states: 2,
                ..CompileLimits::default()
            },
        )
        .expect_err("two consumes plus accept exceed the ceiling");
        assert_eq!(
            budget.kind,
            LowerErrorKind::Compile(CompileErrorKind::StateLimit)
        );
        assert_eq!(budget.actual, Some(3));
        assert_eq!(budget.limit, Some(2));
        assert!(budget.span.byte_end >= budget.span.byte_start);
    }

    #[test]
    fn captures_use_numbered_slot_pairs_and_zero_width_group_boundaries() {
        let program = lower_default("(a)(b)").expect("two captures");
        assert_eq!(program.capture_slots, 4);
        let mut saves = program
            .states
            .iter()
            .filter_map(|state| match state.instruction {
                Instruction::Save { slot, .. } => Some((slot.index(), state.source)),
                _ => None,
            })
            .collect::<Vec<_>>();
        saves.sort_unstable_by_key(|(slot, _)| *slot);
        assert_eq!(
            saves.iter().map(|(slot, _)| *slot).collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert_eq!(saves[0].1, zero_width_span(0, 0));
        assert_eq!(saves[1].1, zero_width_span(3, 3));
        assert_eq!(saves[2].1, zero_width_span(3, 3));
        assert_eq!(saves[3].1, zero_width_span(6, 6));
    }

    #[test]
    fn quantifier_families_are_bounded_and_preserve_greedy_split_priority() {
        for pattern in ["a?", "a*", "a+", "a{0}", "a{3}", "a{2,}", "a{1,3}"] {
            lower_default(pattern)
                .unwrap_or_else(|error| panic!("{pattern} must lower: {error}"))
                .validate(CompileLimits::default())
                .unwrap_or_else(|error| panic!("{pattern} must validate: {error}"));
        }

        let zero = lower_default("a{0}").expect("zero count");
        assert_eq!(zero.resources.classes, 0);
        assert_eq!(zero.resources.states, 2);

        let exact = lower_default("a{3}").expect("exact count");
        assert_eq!(exact.repetition_expansion, 2);
        assert_eq!(exact.resources.classes, 1);

        let greedy = lower_default("a*").expect("greedy star");
        let Instruction::Split { preferred, .. } = greedy.states[greedy.entry.index()].instruction
        else {
            panic!("greedy star entry must split");
        };
        assert!(matches!(
            greedy.states[preferred.index()].instruction,
            Instruction::Consume { .. }
        ));

        let lazy = lower_default("a*?").expect("lazy star");
        let Instruction::Split { preferred, .. } = lazy.states[lazy.entry.index()].instruction
        else {
            panic!("lazy star entry must split");
        };
        assert!(matches!(
            lazy.states[preferred.index()].instruction,
            Instruction::Jump { .. }
        ));
    }

    #[test]
    fn scoped_flags_feed_r3_2_classes_and_hazards_fail_closed() {
        let scoped = lower_default("(?i:a)(?-i:b)").expect("scoped flags");
        assert!(scoped.classes[0].ranges.contains_scalar('A'));
        assert!(scoped.classes[0].ranges.contains_scalar('a'));
        assert!(scoped.classes[1].ranges.contains_scalar('b'));
        assert!(!scoped.classes[1].ranges.contains_scalar('B'));

        let nullable = lower_default("(?:a?)*").expect_err("nullable loop hazard");
        assert_eq!(nullable.kind, LowerErrorKind::NullableUnboundedRepetition);
        assert_eq!(nullable.code(), "RGX-LOWER-E009");

        let erased = lower_default("(a){0}").expect_err("zero repeat erases a capture");
        assert_eq!(erased.kind, LowerErrorKind::CaptureErasedByZeroRepetition);
        assert_eq!(erased.code(), "RGX-LOWER-E010");

        let repetition_limit = lower(
            "(?:ab){4}",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits {
                max_repetition_expansion: 4,
                ..CompileLimits::default()
            },
        )
        .expect_err("three two-state copies exceed four emitted states");
        assert_eq!(
            repetition_limit.kind,
            LowerErrorKind::Compile(CompileErrorKind::RepetitionLimit)
        );
        assert_eq!(repetition_limit.actual, Some(6));
        assert_eq!(repetition_limit.limit, Some(4));
    }
}
