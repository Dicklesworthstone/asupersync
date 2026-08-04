//! Retained-table-backed character semantics for the candidate regex engine.
//!
//! This layer consumes the bounded `ASUP-REGEX-SYNTAX-V1` parser and resolves
//! character-like atoms into canonical, checked ranges. Unicode properties
//! come from the pinned `regex-syntax@0.8.11` Unicode 16.0.0 tables; no table
//! is copied, regenerated, or hand-curated here.
//!
//! The module is deliberately private staging code. It does not compile a
//! matcher, replace the incumbent observability regex, or authorize removing a
//! dependency.

use core::fmt;

use retained_regex_syntax::hir::{Class, HirKind};

use super::regex_syntax::{
    Ast, Escape, Flag, FlagSet, LexErrorKind, LexerLimits, ParseErrorKind, ParserLimits, PerlClass,
    SourceSpan, SyntaxError, Token, TokenKind, lex, parse,
};

pub const SEMANTICS_ID: &str = "ASUP-REGEX-CHAR-SEMANTICS-V1";
pub const RETAINED_TABLE_BACKEND: &str = "regex-syntax@0.8.11";
pub const RETAINED_UNICODE_VERSION: &str = "16.0.0";
pub const DEFAULT_MAX_SEMANTIC_ATOMS: usize = 1_048_576;
pub const DEFAULT_MAX_RANGES_PER_CLASS: usize = 4_096;
pub const DEFAULT_MAX_TOTAL_RANGES: usize = 1_048_576;
pub const DEFAULT_BACKEND_NESTING_LIMIT: u32 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticLimits {
    pub max_semantic_atoms: usize,
    pub max_ranges_per_class: usize,
    pub max_total_ranges: usize,
    pub backend_nesting_limit: u32,
}

impl Default for SemanticLimits {
    fn default() -> Self {
        Self {
            max_semantic_atoms: DEFAULT_MAX_SEMANTIC_ATOMS,
            max_ranges_per_class: DEFAULT_MAX_RANGES_PER_CLASS,
            max_total_ranges: DEFAULT_MAX_TOTAL_RANGES,
            backend_nesting_limit: DEFAULT_BACKEND_NESTING_LIMIT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassOrigin {
    Bracketed,
    Dot,
    Perl(PerlClass),
    UnicodeProperty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassAlphabet {
    UnicodeScalar,
    /// A Unicode-disabled class whose every byte remains ASCII, and therefore
    /// cannot split or fabricate a non-empty UTF-8 match.
    Utf8SafeByte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarRange {
    pub start: char,
    pub end: char,
}

impl ScalarRange {
    pub const fn new(start: char, end: char) -> Self {
        Self { start, end }
    }

    fn cardinality(self) -> u128 {
        let start = u32::from(self.start);
        let end = u32::from(self.end);
        let mut cardinality = u128::from(end - start) + 1;
        let surrogate_start = start.max(0xD800);
        let surrogate_end = end.min(0xDFFF);
        if surrogate_start <= surrogate_end {
            cardinality -= u128::from(surrogate_end - surrogate_start) + 1;
        }
        cardinality
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u8,
    pub end: u8,
}

impl ByteRange {
    pub const fn new(start: u8, end: u8) -> Self {
        Self { start, end }
    }

    fn cardinality(self) -> u128 {
        u128::from(self.end - self.start) + 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalRanges {
    Unicode(Vec<ScalarRange>),
    Bytes(Vec<ByteRange>),
}

impl CanonicalRanges {
    pub fn alphabet(&self) -> ClassAlphabet {
        match self {
            Self::Unicode(_) => ClassAlphabet::UnicodeScalar,
            Self::Bytes(_) => ClassAlphabet::Utf8SafeByte,
        }
    }

    pub fn range_count(&self) -> usize {
        match self {
            Self::Unicode(ranges) => ranges.len(),
            Self::Bytes(ranges) => ranges.len(),
        }
    }

    pub fn cardinality(&self) -> u128 {
        match self {
            Self::Unicode(ranges) => ranges.iter().copied().map(ScalarRange::cardinality).sum(),
            Self::Bytes(ranges) => ranges.iter().copied().map(ByteRange::cardinality).sum(),
        }
    }

    pub fn contains_scalar(&self, value: char) -> bool {
        match self {
            Self::Unicode(ranges) => ranges
                .binary_search_by(|range| {
                    if value < range.start {
                        core::cmp::Ordering::Greater
                    } else if value > range.end {
                        core::cmp::Ordering::Less
                    } else {
                        core::cmp::Ordering::Equal
                    }
                })
                .is_ok(),
            Self::Bytes(ranges) => {
                let codepoint = u32::from(value);
                let Ok(byte) = u8::try_from(codepoint) else {
                    return false;
                };
                ranges
                    .binary_search_by(|range| {
                        if byte < range.start {
                            core::cmp::Ordering::Greater
                        } else if byte > range.end {
                            core::cmp::Ordering::Less
                        } else {
                            core::cmp::Ordering::Equal
                        }
                    })
                    .is_ok()
            }
        }
    }

    pub fn is_canonical(&self) -> bool {
        match self {
            Self::Unicode(ranges) => {
                ranges.windows(2).all(|pair| {
                    pair[0].start <= pair[0].end
                        && pair[1].start <= pair[1].end
                        && u32::from(pair[0].end)
                            .checked_add(1)
                            .is_none_or(|next| next < u32::from(pair[1].start))
                }) && ranges.last().is_none_or(|range| range.start <= range.end)
            }
            Self::Bytes(ranges) => {
                ranges.windows(2).all(|pair| {
                    pair[0].start <= pair[0].end
                        && pair[1].start <= pair[1].end
                        && pair[0]
                            .end
                            .checked_add(1)
                            .is_none_or(|next| next < pair[1].start)
                }) && ranges.last().is_none_or(|range| range.start <= range.end)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalClass {
    pub origin: ClassOrigin,
    pub span: SourceSpan,
    pub ranges: CanonicalRanges,
}

impl CanonicalClass {
    pub fn alphabet(&self) -> ClassAlphabet {
        self.ranges.alphabet()
    }

    pub fn contains_scalar(&self, value: char) -> bool {
        self.ranges.contains_scalar(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticResources {
    pub pattern_bytes: usize,
    pub syntax_tokens: usize,
    pub syntax_nodes: usize,
    pub semantic_atoms: usize,
    pub unicode_property_references: usize,
    pub byte_scopes_validated: usize,
    pub unicode_classes: usize,
    pub byte_classes: usize,
    pub total_ranges: usize,
    pub represented_values: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticAnalysis {
    pub semantics_id: &'static str,
    pub retained_table_backend: &'static str,
    pub retained_unicode_version: &'static str,
    pub ast: Ast,
    pub classes: Vec<CanonicalClass>,
    pub resources: SemanticResources,
}

impl SemanticAnalysis {
    pub fn invariants_hold(&self, pattern: &str, limits: SemanticLimits) -> bool {
        self.semantics_id == SEMANTICS_ID
            && self.retained_table_backend == RETAINED_TABLE_BACKEND
            && self.retained_unicode_version == RETAINED_UNICODE_VERSION
            && self.ast.invariants_hold(pattern)
            && self.resources.pattern_bytes == pattern.len()
            && self.resources.syntax_tokens == self.ast.resources.tokens_consumed
            && self.resources.syntax_nodes == self.ast.resources.ast_nodes
            && self.resources.semantic_atoms == self.classes.len()
            && self.resources.semantic_atoms <= limits.max_semantic_atoms
            && self.resources.total_ranges <= limits.max_total_ranges
            && self.classes.iter().all(|class| {
                class.span.source(pattern).is_some()
                    && class.ranges.range_count() <= limits.max_ranges_per_class
                    && class.ranges.is_canonical()
            })
            && self.resources.total_ranges
                == self
                    .classes
                    .iter()
                    .map(|class| class.ranges.range_count())
                    .sum::<usize>()
            && self.resources.represented_values
                == self
                    .classes
                    .iter()
                    .map(|class| class.ranges.cardinality())
                    .sum::<u128>()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticErrorKind {
    Lex(LexErrorKind),
    Parse(ParseErrorKind),
    UnknownUnicodeProperty,
    UnicodePropertyInByteMode,
    InvalidUtf8Boundary,
    RetainedTableRejected,
    UnexpectedBackendShape,
    SemanticAtomLimit,
    ClassRangeLimit,
    TotalRangeLimit,
    FlagContextInvariant,
}

impl SemanticErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Lex(kind) => kind.code(),
            Self::Parse(kind) => kind.code(),
            Self::UnknownUnicodeProperty => "RGX-SEM-E001",
            Self::UnicodePropertyInByteMode => "RGX-SEM-E002",
            Self::InvalidUtf8Boundary => "RGX-SEM-E003",
            Self::RetainedTableRejected => "RGX-SEM-E004",
            Self::UnexpectedBackendShape => "RGX-SEM-E005",
            Self::SemanticAtomLimit => "RGX-SEM-E006",
            Self::ClassRangeLimit => "RGX-SEM-E007",
            Self::TotalRangeLimit => "RGX-SEM-E008",
            Self::FlagContextInvariant => "RGX-SEM-E009",
        }
    }

    pub const fn diagnostic_category(self) -> &'static str {
        match self {
            Self::Lex(kind) => kind.diagnostic_category(),
            Self::Parse(kind) => kind.diagnostic_category(),
            Self::UnknownUnicodeProperty => "RGX-DIAG-UNKNOWN-UNICODE-PROPERTY",
            Self::UnicodePropertyInByteMode => "RGX-DIAG-UNICODE-PROPERTY-IN-BYTE-MODE",
            Self::InvalidUtf8Boundary => "RGX-DIAG-INVALID-UTF8",
            Self::RetainedTableRejected => "RGX-DIAG-RETAINED-TABLE-REJECTED",
            Self::UnexpectedBackendShape => "RGX-DIAG-SEMANTIC-SHAPE",
            Self::SemanticAtomLimit => "RGX-DIAG-SEMANTIC-ATOM-LIMIT",
            Self::ClassRangeLimit => "RGX-DIAG-CLASS-RANGE-LIMIT",
            Self::TotalRangeLimit => "RGX-DIAG-TOTAL-RANGE-LIMIT",
            Self::FlagContextInvariant => "RGX-DIAG-FLAG-CONTEXT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticError {
    pub kind: SemanticErrorKind,
    pub span: SourceSpan,
}

impl fmt::Display for SemanticError {
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

impl std::error::Error for SemanticError {}

fn syntax_error(error: SyntaxError) -> SemanticError {
    match error {
        SyntaxError::Lex(error) => SemanticError {
            kind: SemanticErrorKind::Lex(error.kind),
            span: error.span,
        },
        SyntaxError::Parse(error) => SemanticError {
            kind: SemanticErrorKind::Parse(error.kind),
            span: error.span,
        },
    }
}

struct SemanticCompiler<'pattern> {
    pattern: &'pattern str,
    tokens: Vec<Token>,
    limits: SemanticLimits,
    classes: Vec<CanonicalClass>,
    unicode_property_references: usize,
    byte_scopes_validated: usize,
    total_ranges: usize,
    represented_values: u128,
}

impl<'pattern> SemanticCompiler<'pattern> {
    fn new(pattern: &'pattern str, tokens: Vec<Token>, limits: SemanticLimits) -> Self {
        Self {
            pattern,
            tokens,
            limits,
            classes: Vec::new(),
            unicode_property_references: 0,
            byte_scopes_validated: 0,
            total_ranges: 0,
            represented_values: 0,
        }
    }

    fn run(mut self, ast: Ast) -> Result<SemanticAnalysis, SemanticError> {
        let mut unicode_context = vec![true];
        let mut index = 0;
        while let Some(token) = self.tokens.get(index).copied() {
            let unicode = unicode_context.last().copied().ok_or(SemanticError {
                kind: SemanticErrorKind::FlagContextInvariant,
                span: token.span,
            })?;
            match token.kind {
                TokenKind::GroupOpen
                | TokenKind::NonCapturingGroupOpen
                | TokenKind::NamedCaptureGroupOpen { .. } => {
                    unicode_context.push(unicode);
                }
                TokenKind::FlagDirective { set, clear, scoped } => {
                    let next = apply_unicode_flag(unicode, set, clear);
                    if scoped {
                        if !next {
                            let close = self.find_group_close(index)?;
                            self.validate_byte_scope(index, close)?;
                        }
                        unicode_context.push(next);
                    } else if let Some(current) = unicode_context.last_mut() {
                        if !next {
                            self.validate_global_byte_scope(index)?;
                        }
                        *current = next;
                    } else {
                        return Err(SemanticError {
                            kind: SemanticErrorKind::FlagContextInvariant,
                            span: token.span,
                        });
                    }
                }
                TokenKind::GroupClose => {
                    if unicode_context.len() <= 1 {
                        return Err(SemanticError {
                            kind: SemanticErrorKind::FlagContextInvariant,
                            span: token.span,
                        });
                    }
                    unicode_context.pop();
                }
                TokenKind::ClassOpen => {
                    let close = self.find_class_close(index)?;
                    self.unicode_property_references = self
                        .unicode_property_references
                        .saturating_add(self.count_unicode_properties(index, close));
                    let span = cover_spans(token.span, self.tokens[close].span);
                    self.compile_atom(span, ClassOrigin::Bracketed, unicode)?;
                    index = close;
                }
                TokenKind::Dot => {
                    self.compile_atom(token.span, ClassOrigin::Dot, unicode)?;
                }
                TokenKind::Escaped(Escape::PerlClass(class)) => {
                    self.compile_atom(token.span, ClassOrigin::Perl(class), unicode)?;
                }
                TokenKind::Escaped(Escape::UnicodeClass { .. }) => {
                    self.unicode_property_references =
                        self.unicode_property_references.saturating_add(1);
                    self.compile_atom(token.span, ClassOrigin::UnicodeProperty, unicode)?;
                }
                TokenKind::End => break,
                _ => {}
            }
            index = index.saturating_add(1);
        }

        let unicode_classes = self
            .classes
            .iter()
            .filter(|class| class.alphabet() == ClassAlphabet::UnicodeScalar)
            .count();
        let byte_classes = self.classes.len().saturating_sub(unicode_classes);
        let resources = SemanticResources {
            pattern_bytes: self.pattern.len(),
            syntax_tokens: ast.resources.tokens_consumed,
            syntax_nodes: ast.resources.ast_nodes,
            semantic_atoms: self.classes.len(),
            unicode_property_references: self.unicode_property_references,
            byte_scopes_validated: self.byte_scopes_validated,
            unicode_classes,
            byte_classes,
            total_ranges: self.total_ranges,
            represented_values: self.represented_values,
        };
        Ok(SemanticAnalysis {
            semantics_id: SEMANTICS_ID,
            retained_table_backend: RETAINED_TABLE_BACKEND,
            retained_unicode_version: RETAINED_UNICODE_VERSION,
            ast,
            classes: self.classes,
            resources,
        })
    }

    fn find_class_close(&self, start: usize) -> Result<usize, SemanticError> {
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
        Err(SemanticError {
            kind: SemanticErrorKind::UnexpectedBackendShape,
            span: self.tokens[start].span,
        })
    }

    fn find_group_close(&self, start: usize) -> Result<usize, SemanticError> {
        let mut depth = 1_usize;
        for (index, token) in self.tokens.iter().enumerate().skip(start + 1) {
            match token.kind {
                TokenKind::GroupOpen
                | TokenKind::NonCapturingGroupOpen
                | TokenKind::NamedCaptureGroupOpen { .. }
                | TokenKind::FlagDirective { scoped: true, .. } => {
                    depth = depth.saturating_add(1);
                }
                TokenKind::GroupClose => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Ok(index);
                    }
                }
                _ => {}
            }
        }
        Err(SemanticError {
            kind: SemanticErrorKind::FlagContextInvariant,
            span: self.tokens[start].span,
        })
    }

    fn validate_byte_scope(&mut self, start: usize, close: usize) -> Result<(), SemanticError> {
        if let Some(property) = self.tokens[start..=close]
            .iter()
            .find(|token| matches!(token.kind, TokenKind::Escaped(Escape::UnicodeClass { .. })))
        {
            return Err(SemanticError {
                kind: SemanticErrorKind::UnicodePropertyInByteMode,
                span: property.span,
            });
        }
        let span = cover_spans(self.tokens[start].span, self.tokens[close].span);
        self.validate_byte_fragment(span)
    }

    fn validate_global_byte_scope(&mut self, start: usize) -> Result<(), SemanticError> {
        let end = self.tokens.len().saturating_sub(1);
        if let Some(property) = self.tokens[start..=end]
            .iter()
            .find(|token| matches!(token.kind, TokenKind::Escaped(Escape::UnicodeClass { .. })))
        {
            return Err(SemanticError {
                kind: SemanticErrorKind::UnicodePropertyInByteMode,
                span: property.span,
            });
        }
        let span = SourceSpan {
            byte_start: self.tokens[start].span.byte_start,
            byte_end: self.pattern.len(),
            scalar_start: self.tokens[start].span.scalar_start,
            scalar_end: self.pattern.chars().count(),
        };
        self.validate_byte_fragment(span)
    }

    fn validate_byte_fragment(&mut self, span: SourceSpan) -> Result<(), SemanticError> {
        let source = span.source(self.pattern).ok_or(SemanticError {
            kind: SemanticErrorKind::FlagContextInvariant,
            span,
        })?;
        let mut builder = retained_regex_syntax::ParserBuilder::new();
        builder
            .nest_limit(self.limits.backend_nesting_limit)
            .utf8(false);
        let hir = builder.build().parse(source).map_err(|_| SemanticError {
            kind: SemanticErrorKind::InvalidUtf8Boundary,
            span,
        })?;
        if !utf8_boundary_safe(&hir) {
            return Err(SemanticError {
                kind: SemanticErrorKind::InvalidUtf8Boundary,
                span,
            });
        }
        self.byte_scopes_validated = self.byte_scopes_validated.saturating_add(1);
        Ok(())
    }

    fn count_unicode_properties(&self, start: usize, end: usize) -> usize {
        self.tokens[start..=end]
            .iter()
            .filter(|token| matches!(token.kind, TokenKind::Escaped(Escape::UnicodeClass { .. })))
            .count()
    }

    fn compile_atom(
        &mut self,
        span: SourceSpan,
        origin: ClassOrigin,
        unicode: bool,
    ) -> Result<(), SemanticError> {
        if self.classes.len() >= self.limits.max_semantic_atoms {
            return Err(SemanticError {
                kind: SemanticErrorKind::SemanticAtomLimit,
                span,
            });
        }
        if origin == ClassOrigin::UnicodeProperty && !unicode {
            return Err(SemanticError {
                kind: SemanticErrorKind::UnicodePropertyInByteMode,
                span,
            });
        }
        let source = span.source(self.pattern).ok_or(SemanticError {
            kind: SemanticErrorKind::UnexpectedBackendShape,
            span,
        })?;
        let mut builder = retained_regex_syntax::ParserBuilder::new();
        builder
            .nest_limit(self.limits.backend_nesting_limit)
            .unicode(unicode)
            .utf8(true);
        let hir = builder.build().parse(source).map_err(|_| SemanticError {
            kind: if origin == ClassOrigin::UnicodeProperty {
                SemanticErrorKind::UnknownUnicodeProperty
            } else if !unicode {
                SemanticErrorKind::InvalidUtf8Boundary
            } else {
                SemanticErrorKind::RetainedTableRejected
            },
            span,
        })?;
        let ranges = ranges_from_hir(&hir, unicode, span)?;
        if ranges.range_count() > self.limits.max_ranges_per_class {
            return Err(SemanticError {
                kind: SemanticErrorKind::ClassRangeLimit,
                span,
            });
        }
        let Some(total_ranges) = self.total_ranges.checked_add(ranges.range_count()) else {
            return Err(SemanticError {
                kind: SemanticErrorKind::TotalRangeLimit,
                span,
            });
        };
        if total_ranges > self.limits.max_total_ranges {
            return Err(SemanticError {
                kind: SemanticErrorKind::TotalRangeLimit,
                span,
            });
        }
        if !ranges.is_canonical() {
            return Err(SemanticError {
                kind: SemanticErrorKind::UnexpectedBackendShape,
                span,
            });
        }
        self.total_ranges = total_ranges;
        self.represented_values = self
            .represented_values
            .checked_add(ranges.cardinality())
            .ok_or(SemanticError {
                kind: SemanticErrorKind::TotalRangeLimit,
                span,
            })?;
        self.classes.push(CanonicalClass {
            origin,
            span,
            ranges,
        });
        Ok(())
    }
}

fn apply_unicode_flag(current: bool, set: FlagSet, clear: FlagSet) -> bool {
    let enabled = if set.contains(Flag::Unicode) {
        true
    } else {
        current
    };
    if clear.contains(Flag::Unicode) {
        false
    } else {
        enabled
    }
}

const fn cover_spans(left: SourceSpan, right: SourceSpan) -> SourceSpan {
    SourceSpan {
        byte_start: left.byte_start,
        byte_end: right.byte_end,
        scalar_start: left.scalar_start,
        scalar_end: right.scalar_end,
    }
}

const UTF8_BOUNDARY: usize = 0;
const UTF8_NEED_ONE: usize = 1;
const UTF8_NEED_TWO: usize = 2;
const UTF8_NEED_THREE: usize = 3;
const UTF8_AFTER_E0: usize = 4;
const UTF8_AFTER_ED: usize = 5;
const UTF8_AFTER_F0: usize = 6;
const UTF8_AFTER_F4: usize = 7;
const UTF8_INVALID: usize = 8;
const UTF8_STATE_COUNT: usize = 9;

#[derive(Clone, Copy)]
struct Utf8Relation {
    rows: [u16; UTF8_STATE_COUNT],
}

impl Utf8Relation {
    const fn empty() -> Self {
        Self {
            rows: [0; UTF8_STATE_COUNT],
        }
    }

    fn identity() -> Self {
        let mut relation = Self::empty();
        for state in 0..UTF8_STATE_COUNT {
            relation.rows[state] = 1_u16 << state;
        }
        relation
    }

    fn union(mut self, other: Self) -> Self {
        for state in 0..UTF8_STATE_COUNT {
            self.rows[state] |= other.rows[state];
        }
        self
    }

    fn then(self, next: Self) -> Self {
        let mut composed = Self::empty();
        for input in 0..UTF8_STATE_COUNT {
            let mut middle = self.rows[input];
            while middle != 0 {
                let state = middle.trailing_zeros() as usize;
                composed.rows[input] |= next.rows[state];
                middle &= middle - 1;
            }
        }
        composed
    }

    fn power(mut self, mut exponent: u32) -> Self {
        let mut result = Self::identity();
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result.then(self);
            }
            exponent >>= 1;
            if exponent != 0 {
                self = self.then(self);
            }
        }
        result
    }

    fn bounded_closure(self, max_power: u32) -> Self {
        let mut closure = Self::identity();
        let mut power = Self::identity();
        for _ in 0..max_power.min(UTF8_STATE_COUNT as u32 * UTF8_STATE_COUNT as u32 + 1) {
            power = power.then(self);
            let expanded = closure.union(power);
            if expanded.rows == closure.rows {
                return closure;
            }
            closure = expanded;
        }
        closure
    }

    fn closure(self) -> Self {
        self.bounded_closure(u32::MAX)
    }
}

fn utf8_step(state: usize, byte: u8) -> usize {
    match state {
        UTF8_BOUNDARY => match byte {
            0x00..=0x7F => UTF8_BOUNDARY,
            0xC2..=0xDF => UTF8_NEED_ONE,
            0xE0 => UTF8_AFTER_E0,
            0xE1..=0xEC | 0xEE..=0xEF => UTF8_NEED_TWO,
            0xED => UTF8_AFTER_ED,
            0xF0 => UTF8_AFTER_F0,
            0xF1..=0xF3 => UTF8_NEED_THREE,
            0xF4 => UTF8_AFTER_F4,
            _ => UTF8_INVALID,
        },
        UTF8_NEED_ONE => {
            if (0x80..=0xBF).contains(&byte) {
                UTF8_BOUNDARY
            } else {
                UTF8_INVALID
            }
        }
        UTF8_NEED_TWO => {
            if (0x80..=0xBF).contains(&byte) {
                UTF8_NEED_ONE
            } else {
                UTF8_INVALID
            }
        }
        UTF8_NEED_THREE => {
            if (0x80..=0xBF).contains(&byte) {
                UTF8_NEED_TWO
            } else {
                UTF8_INVALID
            }
        }
        UTF8_AFTER_E0 => {
            if (0xA0..=0xBF).contains(&byte) {
                UTF8_NEED_ONE
            } else {
                UTF8_INVALID
            }
        }
        UTF8_AFTER_ED => {
            if (0x80..=0x9F).contains(&byte) {
                UTF8_NEED_ONE
            } else {
                UTF8_INVALID
            }
        }
        UTF8_AFTER_F0 => {
            if (0x90..=0xBF).contains(&byte) {
                UTF8_NEED_TWO
            } else {
                UTF8_INVALID
            }
        }
        UTF8_AFTER_F4 => {
            if (0x80..=0x8F).contains(&byte) {
                UTF8_NEED_TWO
            } else {
                UTF8_INVALID
            }
        }
        _ => UTF8_INVALID,
    }
}

fn exact_byte_relation(byte: u8) -> Utf8Relation {
    let mut relation = Utf8Relation::empty();
    for state in 0..UTF8_STATE_COUNT {
        relation.rows[state] = 1_u16 << utf8_step(state, byte);
    }
    relation
}

fn literal_relation(bytes: &[u8]) -> Utf8Relation {
    bytes
        .iter()
        .copied()
        .fold(Utf8Relation::identity(), |relation, byte| {
            relation.then(exact_byte_relation(byte))
        })
}

fn byte_class_relation(class: &retained_regex_syntax::hir::ClassBytes) -> Utf8Relation {
    let mut relation = Utf8Relation::empty();
    for range in class.ranges() {
        for byte in range.start()..=range.end() {
            relation = relation.union(exact_byte_relation(byte));
        }
    }
    relation
}

fn unicode_class_relation(class: &retained_regex_syntax::hir::ClassUnicode) -> Utf8Relation {
    if class.ranges().is_empty() {
        return Utf8Relation::empty();
    }
    let mut relation = Utf8Relation::empty();
    relation.rows[UTF8_BOUNDARY] = 1_u16 << UTF8_BOUNDARY;
    for state in 1..UTF8_STATE_COUNT {
        relation.rows[state] = 1_u16 << UTF8_INVALID;
    }
    relation
}

fn repetition_relation(sub: Utf8Relation, min: u32, max: Option<u32>) -> Utf8Relation {
    let required = sub.power(min);
    match max {
        Some(max) => required.then(sub.bounded_closure(max.saturating_sub(min))),
        None => required.then(sub.closure()),
    }
}

fn utf8_relation(hir: &retained_regex_syntax::hir::Hir) -> Utf8Relation {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Utf8Relation::identity(),
        HirKind::Literal(literal) => literal_relation(&literal.0),
        HirKind::Class(Class::Bytes(class)) => byte_class_relation(class),
        HirKind::Class(Class::Unicode(class)) => unicode_class_relation(class),
        HirKind::Repetition(repetition) => repetition_relation(
            utf8_relation(&repetition.sub),
            repetition.min,
            repetition.max,
        ),
        HirKind::Capture(capture) => utf8_relation(&capture.sub),
        HirKind::Concat(expressions) => expressions
            .iter()
            .fold(Utf8Relation::identity(), |relation, expression| {
                relation.then(utf8_relation(expression))
            }),
        HirKind::Alternation(expressions) => expressions
            .iter()
            .fold(Utf8Relation::empty(), |relation, expression| {
                relation.union(utf8_relation(expression))
            }),
    }
}

fn utf8_boundary_safe(hir: &retained_regex_syntax::hir::Hir) -> bool {
    let outcomes = utf8_relation(hir).rows[UTF8_BOUNDARY];
    outcomes & !(1_u16 << UTF8_BOUNDARY) == 0
}

fn ranges_from_hir(
    hir: &retained_regex_syntax::hir::Hir,
    unicode: bool,
    span: SourceSpan,
) -> Result<CanonicalRanges, SemanticError> {
    match hir.kind() {
        HirKind::Class(Class::Unicode(class)) => Ok(CanonicalRanges::Unicode(
            class
                .ranges()
                .iter()
                .map(|range| ScalarRange::new(range.start(), range.end()))
                .collect(),
        )),
        HirKind::Class(Class::Bytes(class)) => {
            if class.ranges().iter().any(|range| range.end() > 0x7F) {
                return Err(SemanticError {
                    kind: SemanticErrorKind::InvalidUtf8Boundary,
                    span,
                });
            }
            Ok(CanonicalRanges::Bytes(
                class
                    .ranges()
                    .iter()
                    .map(|range| ByteRange::new(range.start(), range.end()))
                    .collect(),
            ))
        }
        HirKind::Literal(literal) if unicode => {
            let text = core::str::from_utf8(&literal.0).map_err(|_| SemanticError {
                kind: SemanticErrorKind::InvalidUtf8Boundary,
                span,
            })?;
            let mut scalars = text.chars();
            let Some(value) = scalars.next() else {
                return Err(SemanticError {
                    kind: SemanticErrorKind::UnexpectedBackendShape,
                    span,
                });
            };
            if scalars.next().is_some() {
                return Err(SemanticError {
                    kind: SemanticErrorKind::UnexpectedBackendShape,
                    span,
                });
            }
            Ok(CanonicalRanges::Unicode(vec![ScalarRange::new(
                value, value,
            )]))
        }
        HirKind::Literal(literal) => {
            let [value] = literal.0.as_ref() else {
                return Err(SemanticError {
                    kind: SemanticErrorKind::UnexpectedBackendShape,
                    span,
                });
            };
            if *value > 0x7F {
                return Err(SemanticError {
                    kind: SemanticErrorKind::InvalidUtf8Boundary,
                    span,
                });
            }
            Ok(CanonicalRanges::Bytes(vec![ByteRange::new(*value, *value)]))
        }
        _ => Err(SemanticError {
            kind: SemanticErrorKind::UnexpectedBackendShape,
            span,
        }),
    }
}

pub fn analyze(
    pattern: &str,
    lexer_limits: LexerLimits,
    parser_limits: ParserLimits,
    semantic_limits: SemanticLimits,
) -> Result<SemanticAnalysis, SemanticError> {
    let ast = parse(pattern, lexer_limits, parser_limits).map_err(syntax_error)?;
    let tokens = lex(pattern, lexer_limits).map_err(|error| SemanticError {
        kind: SemanticErrorKind::Lex(error.kind),
        span: error.span,
    })?;
    SemanticCompiler::new(pattern, tokens, semantic_limits).run(ast)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn default_analyze(pattern: &str) -> Result<SemanticAnalysis, SemanticError> {
        analyze(
            pattern,
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
        )
    }

    fn only_class(pattern: &str) -> CanonicalClass {
        let analysis = default_analyze(pattern).expect("fixture must have valid semantics");
        assert_eq!(analysis.classes.len(), 1);
        analysis.classes[0].clone()
    }

    #[test]
    fn unicode_property_and_set_algebra_use_pinned_tables() {
        let class = only_class(r"[\pL&&\p{Greek}]");
        assert_eq!(class.alphabet(), ClassAlphabet::UnicodeScalar);
        assert!(class.contains_scalar('κ'));
        assert!(class.contains_scalar('Σ'));
        assert!(!class.contains_scalar('A'));
        assert!(class.ranges.is_canonical());
    }

    #[test]
    fn union_negation_ranges_and_ascii_posix_classes_are_canonical() {
        let consonants = only_class("[a-z&&[^aeiou]]");
        assert!(consonants.contains_scalar('b'));
        assert!(consonants.contains_scalar('z'));
        assert!(!consonants.contains_scalar('a'));
        assert!(!consonants.contains_scalar('é'));

        let digits = only_class("[[:digit:]]");
        assert!(digits.contains_scalar('0'));
        assert!(digits.contains_scalar('9'));
        assert!(!digits.contains_scalar('١'));
    }

    #[test]
    fn unicode_and_ascii_perl_classes_preserve_flag_scope() {
        let analysis = default_analyze(r"\d(?-u:\d)\d").expect("scoped classes must compile");
        assert_eq!(analysis.classes.len(), 3);
        assert_eq!(analysis.classes[0].alphabet(), ClassAlphabet::UnicodeScalar);
        assert_eq!(analysis.classes[1].alphabet(), ClassAlphabet::Utf8SafeByte);
        assert_eq!(analysis.classes[2].alphabet(), ClassAlphabet::UnicodeScalar);
        assert!(analysis.classes[0].contains_scalar('١'));
        assert!(!analysis.classes[1].contains_scalar('١'));
        assert!(analysis.classes[1].contains_scalar('7'));
    }

    #[test]
    fn combining_marks_edge_scalars_and_noncharacters_are_explicit() {
        let marks = only_class(r"\p{M}");
        assert!(marks.contains_scalar('\u{0301}'));
        assert!(!marks.contains_scalar('A'));

        let edges = only_class(r"[\u{0}\u{FDD0}\u{10FFFF}]");
        assert!(edges.contains_scalar('\0'));
        assert!(edges.contains_scalar('\u{FDD0}'));
        assert!(edges.contains_scalar('\u{10FFFF}'));
        assert!(!edges.contains_scalar('\u{FFFD}'));
    }

    #[test]
    fn unknown_properties_fail_closed_without_rendering_source() {
        let pattern = r"\p{DefinitelyNotAProperty_private-source-canary}";
        let error = default_analyze(pattern).expect_err("unknown property must fail");
        assert_eq!(error.kind, SemanticErrorKind::UnknownUnicodeProperty);
        assert_eq!(error.kind.code(), "RGX-SEM-E001");
        assert!(!error.to_string().contains("private-source-canary"));
    }

    #[test]
    fn unicode_properties_are_forbidden_when_unicode_mode_is_disabled() {
        let error = default_analyze(r"(?-u:\pL)").expect_err("byte property must fail");
        assert_eq!(error.kind, SemanticErrorKind::UnicodePropertyInByteMode);
        assert_eq!(
            error.kind.diagnostic_category(),
            "RGX-DIAG-UNICODE-PROPERTY-IN-BYTE-MODE"
        );
    }

    #[test]
    fn utf8_safe_byte_classes_are_kept_and_invalid_bytes_are_rejected() {
        let class = only_class(r"(?-u:[a-z])");
        assert_eq!(class.alphabet(), ClassAlphabet::Utf8SafeByte);
        assert!(class.contains_scalar('a'));
        assert!(!class.contains_scalar('é'));

        let error = default_analyze(r"(?-u:\xFF)").expect_err("invalid byte must fail");
        assert_eq!(error.kind, SemanticErrorKind::InvalidUtf8Boundary);
        assert_eq!(error.kind.code(), "RGX-SEM-E003");
    }

    #[test]
    fn byte_mode_accepts_only_sequences_that_preserve_string_utf8() {
        let escaped =
            default_analyze(r"(?-u:\xC2\xA0)").expect("paired byte escapes form valid UTF-8");
        assert_eq!(escaped.resources.byte_scopes_validated, 1);
        assert!(escaped.invariants_hold(r"(?-u:\xC2\xA0)", SemanticLimits::default()));

        let literal = default_analyze("(?-u:é)").expect("raw scalar remains valid UTF-8");
        assert_eq!(literal.resources.byte_scopes_validated, 1);

        for pattern in [r"(?-u:\xC2|\xA0)", r"(?-u:\xC2\xA0*)"] {
            let error = default_analyze(pattern).expect_err("every match must preserve UTF-8");
            assert_eq!(error.kind, SemanticErrorKind::InvalidUtf8Boundary);
        }
    }

    #[test]
    fn semantic_atom_and_range_budgets_fail_before_unbounded_growth() {
        let atom_error = analyze(
            r"\d\s",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits {
                max_semantic_atoms: 1,
                ..SemanticLimits::default()
            },
        )
        .expect_err("second semantic atom must exceed the limit");
        assert_eq!(atom_error.kind, SemanticErrorKind::SemanticAtomLimit);

        let any_pattern = concat!(r"\p{", "any}");
        let any = default_analyze(any_pattern).expect("Unicode scalar universe must compile");
        assert_eq!(any.resources.total_ranges, 1);
        assert_eq!(any.resources.represented_values, 0x11_0000 - 0x800);

        let range_error = analyze(
            r"\p{Greek}",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits {
                max_ranges_per_class: 1,
                ..SemanticLimits::default()
            },
        )
        .expect_err("Greek requires more than one canonical range");
        assert_eq!(range_error.kind, SemanticErrorKind::ClassRangeLimit);
    }

    #[test]
    fn accounting_and_canonical_invariants_reconcile() {
        let pattern = r"[a-z]\p{Greek}(?-u:\w).";
        let analysis = default_analyze(pattern).expect("fixture must compile");
        assert!(analysis.invariants_hold(pattern, SemanticLimits::default()));
        assert_eq!(analysis.resources.semantic_atoms, 4);
        assert_eq!(analysis.resources.unicode_property_references, 1);
        assert_eq!(analysis.resources.byte_scopes_validated, 1);
        assert_eq!(analysis.resources.unicode_classes, 3);
        assert_eq!(analysis.resources.byte_classes, 1);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn ascii_ranges_agree_with_the_closed_interval_model(
            left in b'a'..=b'z',
            right in b'a'..=b'z',
            probe in b'a'..=b'z',
        ) {
            let (start, end) = if left <= right {
                (left, right)
            } else {
                (right, left)
            };
            let pattern = format!("[{}-{}]", char::from(start), char::from(end));
            let class = only_class(&pattern);
            prop_assert_eq!(
                class.contains_scalar(char::from(probe)),
                start <= probe && probe <= end
            );
        }

        #[test]
        fn arbitrary_utf8_semantic_inputs_are_panic_free_and_deterministic(
            scalars in proptest::collection::vec(any::<char>(), 0..64),
        ) {
            let pattern: String = scalars.into_iter().collect();
            let left = default_analyze(&pattern);
            let right = default_analyze(&pattern);
            prop_assert_eq!(left, right);
        }
    }
}
