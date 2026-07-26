//! Checked AST-to-Thompson-IR lowering for the candidate regex compiler.
//!
//! This private R3.3.2 surface consumes the pinned R3.2 character, fold, and
//! boundary analysis. It lowers only structural atoms, concatenation, and
//! ordered alternation. Capture and repetition nodes fail closed for R3.3.3.
//! No incomplete state graph can escape as an executable [`Program`].

use core::fmt;

use super::regex_boundaries::{
    self, BoundaryAssertion, FoldBoundaryAnalysis, FoldBoundaryError, FoldBoundaryErrorKind,
    FoldBoundaryLimits, FoldOutput,
};
use super::regex_ir::{
    ACCOUNTED_PROGRAM_BYTES, ClassId, CompileError, CompileErrorKind, CompileLimits, Instruction,
    IrClass, Program, State, StateId,
};
use super::regex_semantics::{CanonicalClass, CanonicalRanges, ScalarRange, SemanticLimits};
use super::regex_syntax::{AstNodeKind, Escape, LexerLimits, NodeId, ParserLimits, SourceSpan};

pub const LOWERING_ID: &str = "ASUP-REGEX-THOMPSON-LOWERING-V1";
pub const LOWERING_SCHEMA_VERSION: u16 = 1;

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
    UnsupportedCapture,
    UnsupportedRepetition,
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
            Self::UnsupportedCapture => "RGX-LOWER-E007",
            Self::UnsupportedRepetition => "RGX-LOWER-E008",
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
/// [`Program::checked`]. Capture and repetition syntax is deliberately rejected
/// until R3.3.3 supplies its lowering rules.
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

#[derive(Debug)]
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
        let states = self.finish_states()?;
        Program::checked(root.start, accept, states, self.classes, 0, 0, self.limits)
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
            AstNodeKind::Capture { .. } => {
                Err(LowerError::new(LowerErrorKind::UnsupportedCapture, span))
            }
            AstNodeKind::Repetition { .. } => {
                Err(LowerError::new(LowerErrorKind::UnsupportedRepetition, span))
            }
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
                | PendingInstruction::Assert { target, .. } => target,
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
                };
                Ok(State {
                    instruction,
                    source: state.source,
                })
            })
            .collect()
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
    fn r3_3_3_nodes_fail_closed_with_distinct_codes() {
        let capture = lower_default("(a)").expect_err("captures belong to R3.3.3");
        assert_eq!(capture.kind, LowerErrorKind::UnsupportedCapture);
        assert_eq!(capture.code(), "RGX-LOWER-E007");

        let repetition = lower_default("a+").expect_err("repetition belongs to R3.3.3");
        assert_eq!(repetition.kind, LowerErrorKind::UnsupportedRepetition);
        assert_eq!(repetition.code(), "RGX-LOWER-E008");
    }
}
