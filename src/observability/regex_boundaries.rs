//! Retained-table-backed folding and zero-width boundary semantics.
//!
//! This private staging layer extends `ASUP-REGEX-CHAR-SEMANTICS-V1` with
//! Unicode 16.0.0 simple case folding and the incumbent input, line and word
//! boundary rules. It deliberately does not implement matching, full
//! multi-scalar case folding, normalization or locale-sensitive behavior.

use core::fmt;

use retained_regex_syntax::hir::{
    Class, ClassBytes, ClassBytesRange, ClassUnicode, ClassUnicodeRange, Hir, HirKind,
};

use super::regex_semantics::{
    ByteRange, CanonicalRanges, RETAINED_TABLE_BACKEND, RETAINED_UNICODE_VERSION, ScalarRange,
    SemanticAnalysis, SemanticErrorKind, SemanticLimits,
};
use super::regex_syntax::{
    Assertion, Escape, Flag, FlagSet, LexerLimits, ParserLimits, SourceSpan, Token, TokenKind, lex,
};

pub const FOLD_BOUNDARY_ID: &str = "ASUP-REGEX-FOLD-BOUNDARY-V1";
pub const FOLDING_KIND: &str = "UNICODE_SIMPLE_ONE_SCALAR";
pub const MULTI_SCALAR_FOLDS_SUPPORTED: bool = false;
pub const LOCALE_SENSITIVE_FOLDS_SUPPORTED: bool = false;
pub const NORMALIZATION_PERFORMED: bool = false;
pub const DEFAULT_MAX_FOLD_ATOMS: usize = 1_048_576;
pub const DEFAULT_MAX_RANGES_PER_FOLD: usize = 4_096;
pub const DEFAULT_MAX_TOTAL_FOLD_RANGES: usize = 1_048_576;
pub const DEFAULT_MAX_BOUNDARY_ASSERTIONS: usize = 1_048_576;
pub const DEFAULT_BACKEND_NESTING_LIMIT: u32 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldBoundaryLimits {
    pub max_fold_atoms: usize,
    pub max_ranges_per_fold: usize,
    pub max_total_fold_ranges: usize,
    pub max_boundary_assertions: usize,
    pub backend_nesting_limit: u32,
}

impl Default for FoldBoundaryLimits {
    fn default() -> Self {
        Self {
            max_fold_atoms: DEFAULT_MAX_FOLD_ATOMS,
            max_ranges_per_fold: DEFAULT_MAX_RANGES_PER_FOLD,
            max_total_fold_ranges: DEFAULT_MAX_TOTAL_FOLD_RANGES,
            max_boundary_assertions: DEFAULT_MAX_BOUNDARY_ASSERTIONS,
            backend_nesting_limit: DEFAULT_BACKEND_NESTING_LIMIT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoldAlphabet {
    UnicodeScalar,
    Utf8SafeAscii,
    /// Exact bytes admitted only as part of an R3.2.2-validated UTF-8 scope.
    Utf8ValidatedByteSequence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldOutput {
    Ranges(CanonicalRanges),
    ExactBytes(Vec<u8>),
}

impl FoldOutput {
    pub fn alphabet(&self) -> FoldAlphabet {
        match self {
            Self::Ranges(CanonicalRanges::Unicode(_)) => FoldAlphabet::UnicodeScalar,
            Self::Ranges(CanonicalRanges::Bytes(_)) => FoldAlphabet::Utf8SafeAscii,
            Self::ExactBytes(_) => FoldAlphabet::Utf8ValidatedByteSequence,
        }
    }

    pub fn range_count(&self) -> usize {
        match self {
            Self::Ranges(ranges) => ranges.range_count(),
            Self::ExactBytes(_) => 0,
        }
    }

    pub fn represented_alternatives(&self) -> u128 {
        match self {
            Self::Ranges(ranges) => ranges.cardinality(),
            Self::ExactBytes(_) => 1,
        }
    }

    pub fn matches_single_scalar(&self, scalar: char) -> bool {
        match self {
            Self::Ranges(ranges) => ranges.contains_scalar(scalar),
            Self::ExactBytes(bytes) => {
                let mut encoded = [0_u8; 4];
                scalar.encode_utf8(&mut encoded).as_bytes() == bytes.as_slice()
            }
        }
    }

    fn invariants_hold(&self) -> bool {
        match self {
            Self::Ranges(ranges) => ranges.is_canonical(),
            Self::ExactBytes(bytes) => !bytes.is_empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldAtom {
    pub span: SourceSpan,
    pub plain: FoldOutput,
    pub folded: FoldOutput,
}

impl FoldAtom {
    pub fn expanded(&self) -> bool {
        self.plain != self.folded
    }

    pub fn alphabet(&self) -> FoldAlphabet {
        self.folded.alphabet()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryKind {
    InputStart,
    InputEnd,
    LineStartLf,
    LineEndLf,
    LineStartCrlf,
    LineEndCrlf,
    WordAscii,
    NotWordAscii,
    WordUnicode,
    NotWordUnicode,
    WordStartAscii,
    WordEndAscii,
    WordStartUnicode,
    WordEndUnicode,
    WordStartHalfAscii,
    WordEndHalfAscii,
    WordStartHalfUnicode,
    WordEndHalfUnicode,
}

impl BoundaryKind {
    pub fn is_match(self, haystack: &str, offset: usize) -> Result<bool, BoundaryEvalError> {
        if offset > haystack.len() || !haystack.is_char_boundary(offset) {
            return Err(BoundaryEvalError {
                kind: BoundaryEvalErrorKind::InvalidUtf8Offset,
            });
        }
        let bytes = haystack.as_bytes();
        let previous_byte = offset
            .checked_sub(1)
            .and_then(|index| bytes.get(index))
            .copied();
        let next_byte = bytes.get(offset).copied();
        match self {
            Self::InputStart => Ok(offset == 0),
            Self::InputEnd => Ok(offset == haystack.len()),
            Self::LineStartLf => Ok(offset == 0 || previous_byte == Some(b'\n')),
            Self::LineEndLf => Ok(offset == haystack.len() || next_byte == Some(b'\n')),
            Self::LineStartCrlf => Ok(offset == 0
                || previous_byte == Some(b'\n')
                || (previous_byte == Some(b'\r') && next_byte != Some(b'\n'))),
            Self::LineEndCrlf => Ok(offset == haystack.len()
                || next_byte == Some(b'\r')
                || (next_byte == Some(b'\n') && previous_byte != Some(b'\r'))),
            Self::WordAscii
            | Self::NotWordAscii
            | Self::WordStartAscii
            | Self::WordEndAscii
            | Self::WordStartHalfAscii
            | Self::WordEndHalfAscii => {
                let (left, right) = adjacent_word_status(haystack, offset, false)?;
                Ok(match self {
                    Self::WordAscii => left != right,
                    Self::NotWordAscii => left == right,
                    Self::WordStartAscii => !left && right,
                    Self::WordEndAscii => left && !right,
                    Self::WordStartHalfAscii => !left,
                    Self::WordEndHalfAscii => !right,
                    _ => unreachable!("ASCII word variant is exhaustively matched"),
                })
            }
            Self::WordUnicode
            | Self::NotWordUnicode
            | Self::WordStartUnicode
            | Self::WordEndUnicode
            | Self::WordStartHalfUnicode
            | Self::WordEndHalfUnicode => {
                let (left, right) = adjacent_word_status(haystack, offset, true)?;
                Ok(match self {
                    Self::WordUnicode => left != right,
                    Self::NotWordUnicode => left == right,
                    Self::WordStartUnicode => !left && right,
                    Self::WordEndUnicode => left && !right,
                    Self::WordStartHalfUnicode => !left,
                    Self::WordEndHalfUnicode => !right,
                    _ => unreachable!("Unicode word variant is exhaustively matched"),
                })
            }
        }
    }

    pub const fn is_unicode_word(self) -> bool {
        matches!(
            self,
            Self::WordUnicode
                | Self::NotWordUnicode
                | Self::WordStartUnicode
                | Self::WordEndUnicode
                | Self::WordStartHalfUnicode
                | Self::WordEndHalfUnicode
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundaryAssertion {
    pub span: SourceSpan,
    pub kind: BoundaryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldBoundaryResources {
    pub pattern_bytes: usize,
    pub syntax_tokens: usize,
    pub syntax_nodes: usize,
    pub case_insensitive_atoms: usize,
    pub expanded_fold_atoms: usize,
    pub identity_fold_atoms: usize,
    pub total_fold_ranges: usize,
    pub represented_fold_alternatives: u128,
    pub boundary_assertions: usize,
    pub unicode_word_assertions: usize,
    pub ascii_word_assertions: usize,
    pub line_assertions: usize,
    pub input_assertions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldBoundaryAnalysis {
    pub contract_id: &'static str,
    pub folding_kind: &'static str,
    pub retained_table_backend: &'static str,
    pub retained_unicode_version: &'static str,
    pub character_semantics: SemanticAnalysis,
    pub folds: Vec<FoldAtom>,
    pub boundaries: Vec<BoundaryAssertion>,
    pub resources: FoldBoundaryResources,
}

impl FoldBoundaryAnalysis {
    pub fn invariants_hold(
        &self,
        pattern: &str,
        semantic_limits: SemanticLimits,
        limits: FoldBoundaryLimits,
    ) -> bool {
        self.contract_id == FOLD_BOUNDARY_ID
            && self.folding_kind == FOLDING_KIND
            && self.retained_table_backend == RETAINED_TABLE_BACKEND
            && self.retained_unicode_version == RETAINED_UNICODE_VERSION
            && !MULTI_SCALAR_FOLDS_SUPPORTED
            && !LOCALE_SENSITIVE_FOLDS_SUPPORTED
            && !NORMALIZATION_PERFORMED
            && self
                .character_semantics
                .invariants_hold(pattern, semantic_limits)
            && self.resources.pattern_bytes == pattern.len()
            && self.resources.syntax_tokens == self.character_semantics.resources.syntax_tokens
            && self.resources.syntax_nodes == self.character_semantics.resources.syntax_nodes
            && self.resources.case_insensitive_atoms == self.folds.len()
            && self.resources.case_insensitive_atoms <= limits.max_fold_atoms
            && self.resources.expanded_fold_atoms
                == self.folds.iter().filter(|atom| atom.expanded()).count()
            && self.resources.identity_fold_atoms
                == self.folds.iter().filter(|atom| !atom.expanded()).count()
            && self.resources.total_fold_ranges
                == self
                    .folds
                    .iter()
                    .map(|atom| atom.folded.range_count())
                    .sum::<usize>()
            && self.resources.total_fold_ranges <= limits.max_total_fold_ranges
            && self.resources.represented_fold_alternatives
                == self
                    .folds
                    .iter()
                    .map(|atom| atom.folded.represented_alternatives())
                    .sum::<u128>()
            && self.folds.iter().all(|atom| {
                atom.span.source(pattern).is_some()
                    && atom.plain.invariants_hold()
                    && atom.folded.invariants_hold()
                    && atom.folded.range_count() <= limits.max_ranges_per_fold
            })
            && self.resources.boundary_assertions == self.boundaries.len()
            && self.resources.boundary_assertions <= limits.max_boundary_assertions
            && self
                .boundaries
                .iter()
                .all(|boundary| boundary.span.source(pattern).is_some())
            && self.resources.unicode_word_assertions
                == self
                    .boundaries
                    .iter()
                    .filter(|boundary| boundary.kind.is_unicode_word())
                    .count()
            && self.resources.ascii_word_assertions
                == self
                    .boundaries
                    .iter()
                    .filter(|boundary| {
                        matches!(
                            boundary.kind,
                            BoundaryKind::WordAscii
                                | BoundaryKind::NotWordAscii
                                | BoundaryKind::WordStartAscii
                                | BoundaryKind::WordEndAscii
                                | BoundaryKind::WordStartHalfAscii
                                | BoundaryKind::WordEndHalfAscii
                        )
                    })
                    .count()
            && self.resources.line_assertions
                == self
                    .boundaries
                    .iter()
                    .filter(|boundary| {
                        matches!(
                            boundary.kind,
                            BoundaryKind::LineStartLf
                                | BoundaryKind::LineEndLf
                                | BoundaryKind::LineStartCrlf
                                | BoundaryKind::LineEndCrlf
                        )
                    })
                    .count()
            && self.resources.input_assertions
                == self
                    .boundaries
                    .iter()
                    .filter(|boundary| {
                        matches!(
                            boundary.kind,
                            BoundaryKind::InputStart | BoundaryKind::InputEnd
                        )
                    })
                    .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoldBoundaryErrorKind {
    CharacterSemantics(SemanticErrorKind),
    RetainedFoldRejected,
    UnexpectedBackendShape,
    FoldAtomLimit,
    FoldRangeLimit,
    TotalFoldRangeLimit,
    BoundaryLimit,
    FlagContextInvariant,
}

impl FoldBoundaryErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::CharacterSemantics(kind) => kind.code(),
            Self::RetainedFoldRejected => "RGX-FB-E001",
            Self::UnexpectedBackendShape => "RGX-FB-E002",
            Self::FoldAtomLimit => "RGX-FB-E003",
            Self::FoldRangeLimit => "RGX-FB-E004",
            Self::TotalFoldRangeLimit => "RGX-FB-E005",
            Self::BoundaryLimit => "RGX-FB-E006",
            Self::FlagContextInvariant => "RGX-FB-E007",
        }
    }

    pub const fn diagnostic_category(self) -> &'static str {
        match self {
            Self::CharacterSemantics(kind) => kind.diagnostic_category(),
            Self::RetainedFoldRejected => "RGX-DIAG-RETAINED-FOLD-REJECTED",
            Self::UnexpectedBackendShape => "RGX-DIAG-FOLD-SHAPE",
            Self::FoldAtomLimit => "RGX-DIAG-FOLD-ATOM-LIMIT",
            Self::FoldRangeLimit => "RGX-DIAG-FOLD-RANGE-LIMIT",
            Self::TotalFoldRangeLimit => "RGX-DIAG-TOTAL-FOLD-RANGE-LIMIT",
            Self::BoundaryLimit => "RGX-DIAG-BOUNDARY-LIMIT",
            Self::FlagContextInvariant => "RGX-DIAG-FOLD-FLAG-CONTEXT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldBoundaryError {
    pub kind: FoldBoundaryErrorKind,
    pub span: SourceSpan,
}

impl fmt::Display for FoldBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}] {} at bytes {}..{} (scalars {}..{})",
            self.kind.code(),
            self.kind.diagnostic_category(),
            self.span.byte_start,
            self.span.byte_end,
            self.span.scalar_start,
            self.span.scalar_end
        )
    }
}

impl std::error::Error for FoldBoundaryError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryEvalErrorKind {
    InvalidUtf8Offset,
    UnicodeWordTableUnavailable,
}

impl BoundaryEvalErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidUtf8Offset => "RGX-FB-EVAL-E001",
            Self::UnicodeWordTableUnavailable => "RGX-FB-EVAL-E002",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundaryEvalError {
    pub kind: BoundaryEvalErrorKind,
}

impl fmt::Display for BoundaryEvalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}] boundary evaluation failed",
            self.kind.code()
        )
    }
}

impl std::error::Error for BoundaryEvalError {}

fn adjacent_word_status(
    haystack: &str,
    offset: usize,
    unicode: bool,
) -> Result<(bool, bool), BoundaryEvalError> {
    let previous = haystack[..offset].chars().next_back();
    let next = haystack[offset..].chars().next();
    let is_word = |scalar: Option<char>| -> Result<bool, BoundaryEvalError> {
        let Some(scalar) = scalar else {
            return Ok(false);
        };
        if unicode {
            retained_regex_syntax::try_is_word_character(scalar).map_err(|_| BoundaryEvalError {
                kind: BoundaryEvalErrorKind::UnicodeWordTableUnavailable,
            })
        } else {
            Ok(scalar.is_ascii()
                && retained_regex_syntax::is_word_byte(u8::try_from(scalar).unwrap_or_default()))
        }
    };
    Ok((is_word(previous)?, is_word(next)?))
}

#[derive(Debug, Clone, Copy)]
struct FlagState {
    case_insensitive: bool,
    multi_line: bool,
    crlf: bool,
    unicode: bool,
    ignore_whitespace: bool,
}

impl Default for FlagState {
    fn default() -> Self {
        Self {
            case_insensitive: false,
            multi_line: false,
            crlf: false,
            unicode: true,
            ignore_whitespace: false,
        }
    }
}

impl FlagState {
    fn apply(mut self, set: FlagSet, clear: FlagSet) -> Self {
        for (flag, field) in [
            (Flag::CaseInsensitive, &mut self.case_insensitive),
            (Flag::MultiLine, &mut self.multi_line),
            (Flag::Crlf, &mut self.crlf),
            (Flag::Unicode, &mut self.unicode),
            (Flag::IgnoreWhitespace, &mut self.ignore_whitespace),
        ] {
            if set.contains(flag) {
                *field = true;
            }
            if clear.contains(flag) {
                *field = false;
            }
        }
        self
    }
}

struct FoldBoundaryCompiler<'pattern> {
    pattern: &'pattern str,
    tokens: Vec<Token>,
    limits: FoldBoundaryLimits,
    folds: Vec<FoldAtom>,
    boundaries: Vec<BoundaryAssertion>,
    total_fold_ranges: usize,
    represented_fold_alternatives: u128,
}

impl<'pattern> FoldBoundaryCompiler<'pattern> {
    fn new(pattern: &'pattern str, tokens: Vec<Token>, limits: FoldBoundaryLimits) -> Self {
        Self {
            pattern,
            tokens,
            limits,
            folds: Vec::new(),
            boundaries: Vec::new(),
            total_fold_ranges: 0,
            represented_fold_alternatives: 0,
        }
    }

    fn run(
        mut self,
        character_semantics: SemanticAnalysis,
    ) -> Result<FoldBoundaryAnalysis, FoldBoundaryError> {
        let mut flags = vec![FlagState::default()];
        let mut index = 0_usize;
        while let Some(token) = self.tokens.get(index).copied() {
            let state = flags.last().copied().ok_or(FoldBoundaryError {
                kind: FoldBoundaryErrorKind::FlagContextInvariant,
                span: token.span,
            })?;
            match token.kind {
                TokenKind::GroupOpen
                | TokenKind::NonCapturingGroupOpen
                | TokenKind::NamedCaptureGroupOpen { .. } => flags.push(state),
                TokenKind::FlagDirective { set, clear, scoped } => {
                    let next = state.apply(set, clear);
                    if scoped {
                        flags.push(next);
                    } else if let Some(current) = flags.last_mut() {
                        *current = next;
                    } else {
                        return Err(FoldBoundaryError {
                            kind: FoldBoundaryErrorKind::FlagContextInvariant,
                            span: token.span,
                        });
                    }
                }
                TokenKind::GroupClose => {
                    if flags.len() <= 1 {
                        return Err(FoldBoundaryError {
                            kind: FoldBoundaryErrorKind::FlagContextInvariant,
                            span: token.span,
                        });
                    }
                    flags.pop();
                }
                TokenKind::ClassOpen => {
                    let close = self.find_class_close(index)?;
                    if state.case_insensitive {
                        let span = cover_spans(token.span, self.tokens[close].span);
                        self.compile_class(span, state)?;
                    }
                    index = close;
                }
                TokenKind::Literal(value) if state.case_insensitive => {
                    self.compile_literal(token.span, LiteralAtom::Scalar(value), state)?;
                }
                TokenKind::Escaped(escape) if state.case_insensitive => {
                    if let Some(literal) = literal_atom(escape, state.unicode) {
                        self.compile_literal(token.span, literal, state)?;
                    } else if matches!(escape, Escape::PerlClass(_) | Escape::UnicodeClass { .. }) {
                        self.compile_class(token.span, state)?;
                    }
                }
                TokenKind::LineStart => {
                    let kind = if state.multi_line {
                        if state.crlf {
                            BoundaryKind::LineStartCrlf
                        } else {
                            BoundaryKind::LineStartLf
                        }
                    } else {
                        BoundaryKind::InputStart
                    };
                    self.push_boundary(token.span, kind)?;
                }
                TokenKind::LineEnd => {
                    let kind = if state.multi_line {
                        if state.crlf {
                            BoundaryKind::LineEndCrlf
                        } else {
                            BoundaryKind::LineEndLf
                        }
                    } else {
                        BoundaryKind::InputEnd
                    };
                    self.push_boundary(token.span, kind)?;
                }
                TokenKind::Escaped(Escape::Assertion(assertion)) => {
                    self.push_boundary(token.span, boundary_kind(assertion, state.unicode))?;
                }
                TokenKind::End => break,
                _ => {}
            }
            index = index.saturating_add(1);
        }
        if flags.len() != 1 {
            return Err(FoldBoundaryError {
                kind: FoldBoundaryErrorKind::FlagContextInvariant,
                span: self
                    .tokens
                    .last()
                    .map_or_else(empty_span, |token| token.span),
            });
        }

        let expanded_fold_atoms = self.folds.iter().filter(|atom| atom.expanded()).count();
        let case_insensitive_atoms = self.folds.len();
        let unicode_word_assertions = self
            .boundaries
            .iter()
            .filter(|boundary| boundary.kind.is_unicode_word())
            .count();
        let ascii_word_assertions = self
            .boundaries
            .iter()
            .filter(|boundary| {
                matches!(
                    boundary.kind,
                    BoundaryKind::WordAscii
                        | BoundaryKind::NotWordAscii
                        | BoundaryKind::WordStartAscii
                        | BoundaryKind::WordEndAscii
                        | BoundaryKind::WordStartHalfAscii
                        | BoundaryKind::WordEndHalfAscii
                )
            })
            .count();
        let line_assertions = self
            .boundaries
            .iter()
            .filter(|boundary| {
                matches!(
                    boundary.kind,
                    BoundaryKind::LineStartLf
                        | BoundaryKind::LineEndLf
                        | BoundaryKind::LineStartCrlf
                        | BoundaryKind::LineEndCrlf
                )
            })
            .count();
        let input_assertions = self
            .boundaries
            .iter()
            .filter(|boundary| {
                matches!(
                    boundary.kind,
                    BoundaryKind::InputStart | BoundaryKind::InputEnd
                )
            })
            .count();
        let resources = FoldBoundaryResources {
            pattern_bytes: self.pattern.len(),
            syntax_tokens: character_semantics.resources.syntax_tokens,
            syntax_nodes: character_semantics.resources.syntax_nodes,
            case_insensitive_atoms,
            expanded_fold_atoms,
            identity_fold_atoms: case_insensitive_atoms.saturating_sub(expanded_fold_atoms),
            total_fold_ranges: self.total_fold_ranges,
            represented_fold_alternatives: self.represented_fold_alternatives,
            boundary_assertions: self.boundaries.len(),
            unicode_word_assertions,
            ascii_word_assertions,
            line_assertions,
            input_assertions,
        };
        Ok(FoldBoundaryAnalysis {
            contract_id: FOLD_BOUNDARY_ID,
            folding_kind: FOLDING_KIND,
            retained_table_backend: RETAINED_TABLE_BACKEND,
            retained_unicode_version: RETAINED_UNICODE_VERSION,
            character_semantics,
            folds: self.folds,
            boundaries: self.boundaries,
            resources,
        })
    }

    fn find_class_close(&self, start: usize) -> Result<usize, FoldBoundaryError> {
        let mut depth = 0_usize;
        for (index, token) in self.tokens.iter().enumerate().skip(start) {
            match token.kind {
                TokenKind::ClassOpen => depth = depth.saturating_add(1),
                TokenKind::ClassClose => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Ok(index);
                    }
                }
                _ => {}
            }
        }
        Err(FoldBoundaryError {
            kind: FoldBoundaryErrorKind::UnexpectedBackendShape,
            span: self.tokens[start].span,
        })
    }

    fn compile_literal(
        &mut self,
        span: SourceSpan,
        literal: LiteralAtom,
        state: FlagState,
    ) -> Result<(), FoldBoundaryError> {
        let (plain, folded) = literal_outputs(literal, state.unicode, span)?;
        self.push_fold(span, plain, folded)
    }

    fn compile_class(
        &mut self,
        span: SourceSpan,
        state: FlagState,
    ) -> Result<(), FoldBoundaryError> {
        let source = span.source(self.pattern).ok_or(FoldBoundaryError {
            kind: FoldBoundaryErrorKind::UnexpectedBackendShape,
            span,
        })?;
        let plain = parse_atom_output(
            source,
            state,
            false,
            self.limits.backend_nesting_limit,
            span,
        )?;
        let folded =
            parse_atom_output(source, state, true, self.limits.backend_nesting_limit, span)?;
        self.push_fold(span, plain, folded)
    }

    fn push_fold(
        &mut self,
        span: SourceSpan,
        plain: FoldOutput,
        folded: FoldOutput,
    ) -> Result<(), FoldBoundaryError> {
        if self.folds.len() >= self.limits.max_fold_atoms {
            return Err(FoldBoundaryError {
                kind: FoldBoundaryErrorKind::FoldAtomLimit,
                span,
            });
        }
        if folded.range_count() > self.limits.max_ranges_per_fold {
            return Err(FoldBoundaryError {
                kind: FoldBoundaryErrorKind::FoldRangeLimit,
                span,
            });
        }
        let Some(total_fold_ranges) = self.total_fold_ranges.checked_add(folded.range_count())
        else {
            return Err(FoldBoundaryError {
                kind: FoldBoundaryErrorKind::TotalFoldRangeLimit,
                span,
            });
        };
        if total_fold_ranges > self.limits.max_total_fold_ranges {
            return Err(FoldBoundaryError {
                kind: FoldBoundaryErrorKind::TotalFoldRangeLimit,
                span,
            });
        }
        let Some(represented_fold_alternatives) = self
            .represented_fold_alternatives
            .checked_add(folded.represented_alternatives())
        else {
            return Err(FoldBoundaryError {
                kind: FoldBoundaryErrorKind::TotalFoldRangeLimit,
                span,
            });
        };
        if !plain.invariants_hold() || !folded.invariants_hold() {
            return Err(FoldBoundaryError {
                kind: FoldBoundaryErrorKind::UnexpectedBackendShape,
                span,
            });
        }
        self.total_fold_ranges = total_fold_ranges;
        self.represented_fold_alternatives = represented_fold_alternatives;
        self.folds.push(FoldAtom {
            span,
            plain,
            folded,
        });
        Ok(())
    }

    fn push_boundary(
        &mut self,
        span: SourceSpan,
        kind: BoundaryKind,
    ) -> Result<(), FoldBoundaryError> {
        if self.boundaries.len() >= self.limits.max_boundary_assertions {
            return Err(FoldBoundaryError {
                kind: FoldBoundaryErrorKind::BoundaryLimit,
                span,
            });
        }
        self.boundaries.push(BoundaryAssertion { span, kind });
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum LiteralAtom {
    Scalar(char),
    Byte(u8),
}

fn literal_atom(escape: Escape, unicode: bool) -> Option<LiteralAtom> {
    match escape {
        Escape::Literal(value) | Escape::Control(value) | Escape::Unicode(value) => {
            Some(LiteralAtom::Scalar(value))
        }
        Escape::Hex(value) if !unicode => {
            u8::try_from(u32::from(value)).ok().map(LiteralAtom::Byte)
        }
        Escape::Hex(value) => Some(LiteralAtom::Scalar(value)),
        Escape::PerlClass(_) | Escape::UnicodeClass { .. } | Escape::Assertion(_) => None,
    }
}

fn literal_outputs(
    literal: LiteralAtom,
    unicode: bool,
    span: SourceSpan,
) -> Result<(FoldOutput, FoldOutput), FoldBoundaryError> {
    match literal {
        LiteralAtom::Scalar(value) if unicode => {
            let plain_class = ClassUnicode::new(vec![ClassUnicodeRange::new(value, value)]);
            let mut folded_class = plain_class.clone();
            folded_class
                .try_case_fold_simple()
                .map_err(|_| FoldBoundaryError {
                    kind: FoldBoundaryErrorKind::RetainedFoldRejected,
                    span,
                })?;
            Ok((
                FoldOutput::Ranges(unicode_ranges(&plain_class)),
                FoldOutput::Ranges(unicode_ranges(&folded_class)),
            ))
        }
        LiteralAtom::Scalar(value) if value.is_ascii() => {
            byte_literal_outputs(u8::try_from(value).unwrap_or_default())
        }
        LiteralAtom::Scalar(value) => {
            let mut encoded = [0_u8; 4];
            let bytes = value.encode_utf8(&mut encoded).as_bytes().to_vec();
            Ok((
                FoldOutput::ExactBytes(bytes.clone()),
                FoldOutput::ExactBytes(bytes),
            ))
        }
        LiteralAtom::Byte(value) if value.is_ascii() => byte_literal_outputs(value),
        LiteralAtom::Byte(value) => Ok((
            FoldOutput::ExactBytes(vec![value]),
            FoldOutput::ExactBytes(vec![value]),
        )),
    }
}

fn byte_literal_outputs(value: u8) -> Result<(FoldOutput, FoldOutput), FoldBoundaryError> {
    let plain_class = ClassBytes::new(vec![ClassBytesRange::new(value, value)]);
    let mut folded_class = plain_class.clone();
    folded_class.case_fold_simple();
    Ok((
        FoldOutput::Ranges(byte_ranges(&plain_class)),
        FoldOutput::Ranges(byte_ranges(&folded_class)),
    ))
}

fn parse_atom_output(
    source: &str,
    state: FlagState,
    case_insensitive: bool,
    backend_nesting_limit: u32,
    span: SourceSpan,
) -> Result<FoldOutput, FoldBoundaryError> {
    let mut builder = retained_regex_syntax::ParserBuilder::new();
    builder
        .nest_limit(backend_nesting_limit)
        .utf8(true)
        .unicode(state.unicode)
        .case_insensitive(case_insensitive)
        .ignore_whitespace(state.ignore_whitespace);
    let hir = builder
        .build()
        .parse(source)
        .map_err(|_| FoldBoundaryError {
            kind: FoldBoundaryErrorKind::RetainedFoldRejected,
            span,
        })?;
    output_from_hir(&hir, span)
}

fn output_from_hir(hir: &Hir, span: SourceSpan) -> Result<FoldOutput, FoldBoundaryError> {
    match hir.kind() {
        HirKind::Class(Class::Unicode(class)) => Ok(FoldOutput::Ranges(unicode_ranges(class))),
        HirKind::Class(Class::Bytes(class)) => Ok(FoldOutput::Ranges(byte_ranges(class))),
        HirKind::Literal(literal) if !literal.0.is_empty() => {
            Ok(FoldOutput::ExactBytes(literal.0.to_vec()))
        }
        _ => Err(FoldBoundaryError {
            kind: FoldBoundaryErrorKind::UnexpectedBackendShape,
            span,
        }),
    }
}

fn unicode_ranges(class: &ClassUnicode) -> CanonicalRanges {
    CanonicalRanges::Unicode(
        class
            .ranges()
            .iter()
            .map(|range| ScalarRange::new(range.start(), range.end()))
            .collect(),
    )
}

fn byte_ranges(class: &ClassBytes) -> CanonicalRanges {
    CanonicalRanges::Bytes(
        class
            .ranges()
            .iter()
            .map(|range| ByteRange::new(range.start(), range.end()))
            .collect(),
    )
}

const fn boundary_kind(assertion: Assertion, unicode: bool) -> BoundaryKind {
    match assertion {
        Assertion::TextStart => BoundaryKind::InputStart,
        Assertion::TextEnd => BoundaryKind::InputEnd,
        Assertion::WordBoundary if unicode => BoundaryKind::WordUnicode,
        Assertion::WordBoundary => BoundaryKind::WordAscii,
        Assertion::NotWordBoundary if unicode => BoundaryKind::NotWordUnicode,
        Assertion::NotWordBoundary => BoundaryKind::NotWordAscii,
        Assertion::WordStart if unicode => BoundaryKind::WordStartUnicode,
        Assertion::WordStart => BoundaryKind::WordStartAscii,
        Assertion::WordEnd if unicode => BoundaryKind::WordEndUnicode,
        Assertion::WordEnd => BoundaryKind::WordEndAscii,
        Assertion::WordStartHalf if unicode => BoundaryKind::WordStartHalfUnicode,
        Assertion::WordStartHalf => BoundaryKind::WordStartHalfAscii,
        Assertion::WordEndHalf if unicode => BoundaryKind::WordEndHalfUnicode,
        Assertion::WordEndHalf => BoundaryKind::WordEndHalfAscii,
        Assertion::AsciiWordStart => BoundaryKind::WordStartAscii,
        Assertion::AsciiWordEnd => BoundaryKind::WordEndAscii,
    }
}

fn cover_spans(left: SourceSpan, right: SourceSpan) -> SourceSpan {
    SourceSpan {
        byte_start: left.byte_start.min(right.byte_start),
        byte_end: left.byte_end.max(right.byte_end),
        scalar_start: left.scalar_start.min(right.scalar_start),
        scalar_end: left.scalar_end.max(right.scalar_end),
    }
}

const fn empty_span() -> SourceSpan {
    SourceSpan {
        byte_start: 0,
        byte_end: 0,
        scalar_start: 0,
        scalar_end: 0,
    }
}

pub fn analyze(
    pattern: &str,
    lexer_limits: LexerLimits,
    parser_limits: ParserLimits,
    semantic_limits: SemanticLimits,
    limits: FoldBoundaryLimits,
) -> Result<FoldBoundaryAnalysis, FoldBoundaryError> {
    let character_semantics =
        super::regex_semantics::analyze(pattern, lexer_limits, parser_limits, semantic_limits)
            .map_err(|error| FoldBoundaryError {
                kind: FoldBoundaryErrorKind::CharacterSemantics(error.kind),
                span: error.span,
            })?;
    let tokens = lex(pattern, lexer_limits).map_err(|error| FoldBoundaryError {
        kind: FoldBoundaryErrorKind::CharacterSemantics(SemanticErrorKind::Lex(error.kind)),
        span: error.span,
    })?;
    FoldBoundaryCompiler::new(pattern, tokens, limits).run(character_semantics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn default_analyze(pattern: &str) -> Result<FoldBoundaryAnalysis, FoldBoundaryError> {
        analyze(
            pattern,
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
        )
    }

    #[test]
    fn ascii_simple_fold_and_flag_scope_are_exact() {
        let analysis = default_analyze("a(?i:b)(?-i:c)(?i-u:d)").expect("valid folding fixture");
        assert_eq!(analysis.folds.len(), 2);
        assert!(analysis.folds[0].folded.matches_single_scalar('b'));
        assert!(analysis.folds[0].folded.matches_single_scalar('B'));
        assert_eq!(analysis.folds[0].alphabet(), FoldAlphabet::UnicodeScalar);
        assert!(analysis.folds[1].folded.matches_single_scalar('d'));
        assert!(analysis.folds[1].folded.matches_single_scalar('D'));
        assert_eq!(analysis.folds[1].alphabet(), FoldAlphabet::Utf8SafeAscii);
        assert_eq!(analysis.resources.expanded_fold_atoms, 2);
    }

    #[test]
    fn unicode_simple_fold_uses_sigma_and_kelvin_equivalence() {
        let sigma = default_analyze("(?i:σ)").expect("sigma fold must compile");
        let sigma = &sigma.folds[0].folded;
        assert!(sigma.matches_single_scalar('σ'));
        assert!(sigma.matches_single_scalar('Σ'));
        assert!(sigma.matches_single_scalar('ς'));

        let kelvin = default_analyze("(?i:k)").expect("Kelvin fold must compile");
        let kelvin = &kelvin.folds[0].folded;
        assert!(kelvin.matches_single_scalar('k'));
        assert!(kelvin.matches_single_scalar('K'));
        assert!(kelvin.matches_single_scalar('\u{212A}'));
    }

    #[test]
    fn multi_scalar_locale_and_normalization_expansions_are_explicitly_absent() {
        assert_eq!(FOLDING_KIND, "UNICODE_SIMPLE_ONE_SCALAR");
        assert!(!MULTI_SCALAR_FOLDS_SUPPORTED);
        assert!(!LOCALE_SENSITIVE_FOLDS_SUPPORTED);
        assert!(!NORMALIZATION_PERFORMED);

        let sharp_s = default_analyze("(?i:ß)").expect("simple sharp-s semantics must compile");
        assert_eq!(sharp_s.folds.len(), 1);
        assert!(sharp_s.folds[0].folded.matches_single_scalar('ß'));
        assert!(!sharp_s.folds[0].folded.matches_single_scalar('s'));

        let decomposed = default_analyze("(?i:e\u{301})").expect("combining sequence must compile");
        assert_eq!(decomposed.folds.len(), 2);
        assert!(decomposed.folds[1].folded.matches_single_scalar('\u{301}'));
        assert!(!decomposed.folds[1].expanded());
    }

    #[test]
    fn byte_mode_folds_ascii_only_and_preserves_validated_non_ascii_bytes() {
        let ascii = default_analyze("(?i-u:a)").expect("ASCII byte fold must compile");
        assert_eq!(ascii.folds[0].alphabet(), FoldAlphabet::Utf8SafeAscii);
        assert!(ascii.folds[0].folded.matches_single_scalar('A'));
        assert!(!ascii.folds[0].folded.matches_single_scalar('\u{212A}'));

        let non_ascii = default_analyze("(?i-u:é)").expect("UTF-8 literal scope must compile");
        assert_eq!(
            non_ascii.folds[0].alphabet(),
            FoldAlphabet::Utf8ValidatedByteSequence
        );
        assert!(!non_ascii.folds[0].expanded());
        assert!(non_ascii.folds[0].folded.matches_single_scalar('é'));
        assert!(!non_ascii.folds[0].folded.matches_single_scalar('É'));
    }

    #[test]
    fn folded_classes_are_canonical_and_bounded() {
        let analysis = default_analyze(r"(?i:[a-z&&[^q]])").expect("folded class must compile");
        assert_eq!(analysis.folds.len(), 1);
        let fold = &analysis.folds[0];
        assert!(fold.expanded());
        assert!(fold.folded.matches_single_scalar('A'));
        assert!(!fold.folded.matches_single_scalar('Q'));
        assert!(fold.folded.invariants_hold());
        assert!(analysis.invariants_hold(
            r"(?i:[a-z&&[^q]])",
            SemanticLimits::default(),
            FoldBoundaryLimits::default()
        ));
    }

    #[test]
    fn input_and_lf_line_boundaries_cover_empty_and_newline_inputs() {
        for kind in [BoundaryKind::InputStart, BoundaryKind::InputEnd] {
            assert!(kind.is_match("", 0).expect("valid boundary"));
        }
        assert!(
            BoundaryKind::LineStartLf
                .is_match("a\nb", 2)
                .expect("valid boundary")
        );
        assert!(
            BoundaryKind::LineEndLf
                .is_match("a\nb", 1)
                .expect("valid boundary")
        );
        assert!(
            !BoundaryKind::LineStartLf
                .is_match("a\nb", 1)
                .expect("valid boundary")
        );
        assert!(
            !BoundaryKind::LineEndLf
                .is_match("a\nb", 2)
                .expect("valid boundary")
        );
    }

    #[test]
    fn crlf_boundaries_never_split_a_pair_but_accept_lone_terminators() {
        let crlf = "a\r\nb";
        assert!(
            BoundaryKind::LineEndCrlf
                .is_match(crlf, 1)
                .expect("before CR")
        );
        assert!(
            !BoundaryKind::LineEndCrlf
                .is_match(crlf, 2)
                .expect("between CRLF")
        );
        assert!(
            !BoundaryKind::LineStartCrlf
                .is_match(crlf, 2)
                .expect("between CRLF")
        );
        assert!(
            BoundaryKind::LineStartCrlf
                .is_match(crlf, 3)
                .expect("after LF")
        );

        assert!(
            BoundaryKind::LineStartCrlf
                .is_match("a\rb", 2)
                .expect("after lone CR")
        );
        assert!(
            BoundaryKind::LineEndCrlf
                .is_match("a\nb", 1)
                .expect("before lone LF")
        );
    }

    #[test]
    fn unicode_and_ascii_word_transitions_differ_without_locale() {
        let greek = " κόσμος ";
        assert!(
            BoundaryKind::WordUnicode
                .is_match(greek, 1)
                .expect("Unicode table available")
        );
        assert!(
            !BoundaryKind::WordAscii
                .is_match(greek, 1)
                .expect("ASCII boundary")
        );

        let combining = " \u{301} ";
        assert!(
            BoundaryKind::WordUnicode
                .is_match(combining, 1)
                .expect("mark is Unicode word")
        );
        assert!(
            !BoundaryKind::WordAscii
                .is_match(combining, 1)
                .expect("mark is not ASCII word")
        );

        assert!(
            BoundaryKind::WordAscii
                .is_match("$a", 1)
                .expect("ASCII start")
        );
        assert!(
            BoundaryKind::NotWordAscii
                .is_match("aa", 1)
                .expect("inside word")
        );
    }

    #[test]
    fn directional_and_half_word_variants_have_distinct_truth_tables() {
        assert!(
            BoundaryKind::WordStartUnicode
                .is_match("-β", 1)
                .expect("word start")
        );
        assert!(
            !BoundaryKind::WordEndUnicode
                .is_match("-β", 1)
                .expect("not word end")
        );
        assert!(
            BoundaryKind::WordEndUnicode
                .is_match("β-", 2)
                .expect("word end")
        );
        assert!(
            BoundaryKind::WordStartHalfUnicode
                .is_match("--", 1)
                .expect("left is non-word")
        );
        assert!(
            BoundaryKind::WordEndHalfUnicode
                .is_match("--", 1)
                .expect("right is non-word")
        );
    }

    #[test]
    fn parser_flags_select_exact_boundary_variants_and_restore_scope() {
        let pattern =
            r"^\A(?m:^$(?R:$))$(?-u:\b\B\b{start}\b{end}\b{start-half}\b{end-half})\b\<\>\z";
        let analysis = default_analyze(pattern).expect("boundary fixture must compile");
        let kinds = analysis
            .boundaries
            .iter()
            .map(|boundary| boundary.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                BoundaryKind::InputStart,
                BoundaryKind::InputStart,
                BoundaryKind::LineStartLf,
                BoundaryKind::LineEndLf,
                BoundaryKind::LineEndCrlf,
                BoundaryKind::InputEnd,
                BoundaryKind::WordAscii,
                BoundaryKind::NotWordAscii,
                BoundaryKind::WordStartAscii,
                BoundaryKind::WordEndAscii,
                BoundaryKind::WordStartHalfAscii,
                BoundaryKind::WordEndHalfAscii,
                BoundaryKind::WordUnicode,
                BoundaryKind::WordStartAscii,
                BoundaryKind::WordEndAscii,
                BoundaryKind::InputEnd,
            ]
        );
        assert!(analysis.invariants_hold(
            pattern,
            SemanticLimits::default(),
            FoldBoundaryLimits::default()
        ));
    }

    #[test]
    fn invalid_utf8_offsets_fail_closed_without_source_echo() {
        let error = BoundaryKind::WordUnicode
            .is_match("é", 1)
            .expect_err("mid-scalar offset must fail");
        assert_eq!(error.kind, BoundaryEvalErrorKind::InvalidUtf8Offset);
        assert_eq!(
            error.to_string(),
            "[RGX-FB-EVAL-E001] boundary evaluation failed"
        );
    }

    #[test]
    fn atom_range_total_and_boundary_budgets_fail_before_growth() {
        let atom_error = analyze(
            "(?i:ab)",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits {
                max_fold_atoms: 1,
                ..FoldBoundaryLimits::default()
            },
        )
        .expect_err("second fold atom must exceed budget");
        assert_eq!(atom_error.kind, FoldBoundaryErrorKind::FoldAtomLimit);

        let range_error = analyze(
            "(?i:a)",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits {
                max_ranges_per_fold: 1,
                ..FoldBoundaryLimits::default()
            },
        )
        .expect_err("ASCII case fold needs two singleton ranges");
        assert_eq!(range_error.kind, FoldBoundaryErrorKind::FoldRangeLimit);

        let total_error = analyze(
            "(?i:ab)",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits {
                max_total_fold_ranges: 2,
                ..FoldBoundaryLimits::default()
            },
        )
        .expect_err("aggregate ranges must exceed budget");
        assert_eq!(total_error.kind, FoldBoundaryErrorKind::TotalFoldRangeLimit);

        let boundary_error = analyze(
            r"\b\B",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits {
                max_boundary_assertions: 1,
                ..FoldBoundaryLimits::default()
            },
        )
        .expect_err("second boundary must exceed budget");
        assert_eq!(boundary_error.kind, FoldBoundaryErrorKind::BoundaryLimit);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn ascii_simple_fold_matches_independent_model(byte in 0_u8..=127) {
            let scalar = char::from(byte);
            let (plain, folded) = literal_outputs(
                LiteralAtom::Scalar(scalar),
                true,
                empty_span(),
            ).expect("retained ASCII fold available");
            prop_assert!(plain.matches_single_scalar(scalar));
            prop_assert!(folded.matches_single_scalar(scalar));
            if scalar.is_ascii_alphabetic() {
                prop_assert!(folded.matches_single_scalar(scalar.to_ascii_lowercase()));
                prop_assert!(folded.matches_single_scalar(scalar.to_ascii_uppercase()));
            } else {
                prop_assert_eq!(plain, folded);
            }
        }

        #[test]
        fn arbitrary_utf8_boundary_evaluation_is_deterministic_and_contained(
            haystack in any::<String>(),
            selector in any::<usize>(),
        ) {
            let boundaries = haystack
                .char_indices()
                .map(|(offset, _)| offset)
                .chain(core::iter::once(haystack.len()))
                .collect::<Vec<_>>();
            let offset = boundaries[selector % boundaries.len()];
            for kind in [
                BoundaryKind::InputStart,
                BoundaryKind::InputEnd,
                BoundaryKind::LineStartLf,
                BoundaryKind::LineEndLf,
                BoundaryKind::LineStartCrlf,
                BoundaryKind::LineEndCrlf,
                BoundaryKind::WordAscii,
                BoundaryKind::NotWordAscii,
                BoundaryKind::WordUnicode,
                BoundaryKind::NotWordUnicode,
            ] {
                let first = kind.is_match(&haystack, offset);
                let second = kind.is_match(&haystack, offset);
                prop_assert_eq!(first, second);
            }
        }
    }
}
