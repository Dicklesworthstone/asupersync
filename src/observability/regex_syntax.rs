//! Strictly safe, resource-bounded lexer for the candidate observability regex engine.
//!
//! This is an internal staging surface for `ASUP-REGEX-SYNTAX-V1`. It does not
//! compile or match patterns, and it is not wired into the incumbent
//! observability filter. The follow-on parser consumes these tokens.

use core::fmt;
use std::collections::BTreeMap;
use std::ops::Range;

pub const GRAMMAR_ID: &str = "ASUP-REGEX-SYNTAX-V1";
pub const DEFAULT_MAX_PATTERN_BYTES: usize = 1_048_576;
pub const DEFAULT_MAX_TOKENS: usize = 1_048_576;
pub const DEFAULT_MAX_AST_NODES: usize = 1_048_576;
pub const DEFAULT_MAX_NESTING: usize = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexerLimits {
    pub max_pattern_bytes: usize,
    /// Maximum number of tokens, including the explicit end-of-input token.
    pub max_tokens: usize,
}

impl Default for LexerLimits {
    fn default() -> Self {
        Self {
            max_pattern_bytes: DEFAULT_MAX_PATTERN_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    pub byte_start: usize,
    pub byte_end: usize,
    pub scalar_start: usize,
    pub scalar_end: usize,
}

impl SourceSpan {
    pub fn byte_range(self) -> Range<usize> {
        self.byte_start..self.byte_end
    }

    pub fn source(self, pattern: &str) -> Option<&str> {
        pattern.get(self.byte_range())
    }

    fn empty_at(byte: usize, scalar: usize) -> Self {
        Self {
            byte_start: byte,
            byte_end: byte,
            scalar_start: scalar,
            scalar_end: scalar,
        }
    }

    fn cover(self, other: Self) -> Self {
        Self {
            byte_start: self.byte_start.min(other.byte_start),
            byte_end: self.byte_end.max(other.byte_end),
            scalar_start: self.scalar_start.min(other.scalar_start),
            scalar_end: self.scalar_end.max(other.scalar_end),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    CaseInsensitive,
    MultiLine,
    DotMatchesNewLine,
    Crlf,
    SwapGreed,
    Unicode,
    IgnoreWhitespace,
}

impl Flag {
    fn from_char(value: char) -> Option<Self> {
        match value {
            'i' => Some(Self::CaseInsensitive),
            'm' => Some(Self::MultiLine),
            's' => Some(Self::DotMatchesNewLine),
            'R' => Some(Self::Crlf),
            'U' => Some(Self::SwapGreed),
            'u' => Some(Self::Unicode),
            'x' => Some(Self::IgnoreWhitespace),
            _ => None,
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::CaseInsensitive => 1 << 0,
            Self::MultiLine => 1 << 1,
            Self::DotMatchesNewLine => 1 << 2,
            Self::Crlf => 1 << 3,
            Self::SwapGreed => 1 << 4,
            Self::Unicode => 1 << 5,
            Self::IgnoreWhitespace => 1 << 6,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FlagSet(u8);

impl FlagSet {
    fn insert(&mut self, flag: Flag) {
        self.0 |= flag.bit();
    }

    pub const fn contains(self, flag: Flag) -> bool {
        self.0 & flag.bit() != 0
    }

    fn remove(&mut self, flag: Flag) {
        self.0 &= !flag.bit();
    }

    fn apply(mut self, set: Self, clear: Self) -> Self {
        for flag in [
            Flag::CaseInsensitive,
            Flag::MultiLine,
            Flag::DotMatchesNewLine,
            Flag::Crlf,
            Flag::SwapGreed,
            Flag::Unicode,
            Flag::IgnoreWhitespace,
        ] {
            if set.contains(flag) {
                self.insert(flag);
            }
            if clear.contains(flag) {
                self.remove(flag);
            }
        }
        self
    }

    fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    fn regex_default() -> Self {
        let mut flags = Self::default();
        flags.insert(Flag::Unicode);
        flags
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedCaptureStyle {
    Python,
    Angle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepetitionRange {
    Exact(u32),
    AtLeast(u32),
    Bounded { min: u32, max: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerlClass {
    Digit,
    NotDigit,
    Space,
    NotSpace,
    Word,
    NotWord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assertion {
    TextStart,
    TextEnd,
    WordBoundary,
    NotWordBoundary,
    WordStart,
    WordEnd,
    WordStartHalf,
    WordEndHalf,
    AsciiWordStart,
    AsciiWordEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escape {
    Literal(char),
    Control(char),
    Hex(char),
    Unicode(char),
    PerlClass(PerlClass),
    UnicodeClass { negated: bool, name: SourceSpan },
    Assertion(Assertion),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Literal(char),
    Alternation,
    Dot,
    GroupOpen,
    GroupClose,
    NonCapturingGroupOpen,
    NamedCaptureGroupOpen {
        style: NamedCaptureStyle,
        name: SourceSpan,
    },
    FlagDirective {
        set: FlagSet,
        clear: FlagSet,
        scoped: bool,
    },
    ClassOpen,
    ClassClose,
    ClassNegation,
    ClassRange,
    ClassIntersection,
    ClassDifference,
    ClassSymmetricDifference,
    PosixClass {
        negated: bool,
        name: SourceSpan,
    },
    ZeroOrOne,
    ZeroOrMore,
    OneOrMore,
    Counted(RepetitionRange),
    LineStart,
    LineEnd,
    Escaped(Escape),
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: SourceSpan,
}

impl Token {
    pub fn source(self, pattern: &str) -> Option<&str> {
        self.span.source(pattern)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexErrorKind {
    PatternTooLarge,
    TokenLimit,
    TrailingEscape,
    MalformedEscape,
    InvalidUnicodeScalar,
    UnsupportedBackreference,
    UnsupportedLookaround,
    MalformedGroupPrefix,
    InvalidFlag,
    InvalidRepetition,
}

impl LexErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PatternTooLarge => "RGX-LEX-E001",
            Self::TokenLimit => "RGX-LEX-E002",
            Self::TrailingEscape => "RGX-LEX-E003",
            Self::MalformedEscape => "RGX-LEX-E004",
            Self::InvalidUnicodeScalar => "RGX-LEX-E005",
            Self::UnsupportedBackreference => "RGX-LEX-E006",
            Self::UnsupportedLookaround => "RGX-LEX-E007",
            Self::MalformedGroupPrefix => "RGX-LEX-E008",
            Self::InvalidFlag => "RGX-LEX-E009",
            Self::InvalidRepetition => "RGX-LEX-E010",
        }
    }

    pub const fn diagnostic_category(self) -> &'static str {
        match self {
            Self::PatternTooLarge => "RGX-DIAG-PATTERN-TOO-LARGE",
            Self::TokenLimit => "RGX-DIAG-TOKEN-LIMIT",
            Self::TrailingEscape | Self::MalformedEscape => "RGX-DIAG-TRAILING-ESCAPE",
            Self::InvalidUnicodeScalar => "RGX-DIAG-INVALID-UTF8",
            Self::UnsupportedBackreference => "RGX-DIAG-UNSUPPORTED-BACKREFERENCE",
            Self::UnsupportedLookaround => "RGX-DIAG-UNSUPPORTED-LOOKAROUND",
            Self::MalformedGroupPrefix => "RGX-DIAG-UNCLOSED-GROUP",
            Self::InvalidFlag => "RGX-DIAG-INVALID-FLAG",
            Self::InvalidRepetition => "RGX-DIAG-INVALID-REPETITION",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LexError {
    pub kind: LexErrorKind,
    pub span: SourceSpan,
}

impl fmt::Display for LexError {
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

impl std::error::Error for LexError {}

#[derive(Debug, Clone, Copy)]
struct Mark {
    byte: usize,
    scalar: usize,
}

struct Cursor<'source> {
    source: &'source str,
    byte: usize,
    scalar: usize,
}

impl<'source> Cursor<'source> {
    fn new(source: &'source str) -> Self {
        Self {
            source,
            byte: 0,
            scalar: 0,
        }
    }

    const fn mark(&self) -> Mark {
        Mark {
            byte: self.byte,
            scalar: self.scalar,
        }
    }

    fn span_from(&self, start: Mark) -> SourceSpan {
        SourceSpan {
            byte_start: start.byte,
            byte_end: self.byte,
            scalar_start: start.scalar,
            scalar_end: self.scalar,
        }
    }

    fn peek(&self) -> Option<char> {
        self.source.get(self.byte..)?.chars().next()
    }

    fn starts_with(&self, value: &str) -> bool {
        self.source
            .get(self.byte..)
            .is_some_and(|tail| tail.starts_with(value))
    }

    fn bump(&mut self) -> Option<char> {
        let value = self.peek()?;
        self.byte = self.byte.saturating_add(value.len_utf8());
        self.scalar = self.scalar.saturating_add(1);
        Some(value)
    }

    fn consume(&mut self, value: &str) -> bool {
        if !self.starts_with(value) {
            return false;
        }
        self.byte = self.byte.saturating_add(value.len());
        self.scalar = self.scalar.saturating_add(value.chars().count());
        true
    }
}

#[derive(Debug, Clone, Copy)]
struct ClassFrame {
    first_atom: bool,
    negation_allowed: bool,
}

impl ClassFrame {
    const fn new() -> Self {
        Self {
            first_atom: true,
            negation_allowed: true,
        }
    }
}

struct Lexer<'source> {
    cursor: Cursor<'source>,
    limits: LexerLimits,
    tokens: Vec<Token>,
    classes: Vec<ClassFrame>,
    /// The effective `x` flag for each open expression scope, including root.
    ignore_whitespace: Vec<bool>,
}

impl<'source> Lexer<'source> {
    fn new(pattern: &'source str, limits: LexerLimits) -> Self {
        // Avoid capacity proportional to attacker-controlled input. The vector
        // grows geometrically only after each token has passed the hard budget.
        let initial_capacity = pattern.len().min(limits.max_tokens).min(4_096);
        Self {
            cursor: Cursor::new(pattern),
            limits,
            tokens: Vec::with_capacity(initial_capacity),
            classes: Vec::new(),
            ignore_whitespace: vec![false],
        }
    }

    fn run(mut self) -> Result<Vec<Token>, LexError> {
        loop {
            self.skip_ignored();
            if self.cursor.peek().is_none() {
                break;
            }
            if self.classes.is_empty() {
                self.lex_top_level()?;
            } else {
                self.lex_class()?;
            }
        }
        let end = self.cursor.mark();
        self.emit(TokenKind::End, end)?;
        Ok(self.tokens)
    }

    fn ignores_whitespace(&self) -> bool {
        self.ignore_whitespace.last().copied().unwrap_or(false)
    }

    fn set_ignore_whitespace(&mut self, enabled: bool) {
        if let Some(current) = self.ignore_whitespace.last_mut() {
            *current = enabled;
        }
    }

    fn push_ignore_whitespace(&mut self, enabled: bool) {
        self.ignore_whitespace.push(enabled);
    }

    fn pop_ignore_whitespace(&mut self) {
        if self.ignore_whitespace.len() > 1 {
            self.ignore_whitespace.pop();
        }
    }

    /// Skip verbose-mode whitespace and line comments without copying source.
    ///
    /// Calls are deliberately placed only at grammar boundaries. Escaped
    /// whitespace and `#` therefore remain literals, while ignored bytes still
    /// contribute to the original byte/scalar spans used by diagnostics.
    fn skip_ignored(&mut self) {
        if !self.ignores_whitespace() {
            return;
        }
        loop {
            while self.cursor.peek().is_some_and(char::is_whitespace) {
                self.cursor.bump();
            }
            if self.cursor.peek() != Some('#') {
                break;
            }
            while let Some(value) = self.cursor.bump() {
                if value == '\n' {
                    break;
                }
            }
        }
    }

    fn error(&self, kind: LexErrorKind, start: Mark) -> LexError {
        LexError {
            kind,
            span: self.cursor.span_from(start),
        }
    }

    fn emit(&mut self, kind: TokenKind, start: Mark) -> Result<(), LexError> {
        let span = self.cursor.span_from(start);
        if self.tokens.len() >= self.limits.max_tokens {
            return Err(LexError {
                kind: LexErrorKind::TokenLimit,
                span,
            });
        }
        self.tokens.push(Token { kind, span });
        Ok(())
    }

    fn mark_class_atom(&mut self) {
        if let Some(frame) = self.classes.last_mut() {
            frame.first_atom = false;
            frame.negation_allowed = false;
        }
    }

    fn lex_top_level(&mut self) -> Result<(), LexError> {
        let start = self.cursor.mark();
        let Some(value) = self.cursor.peek() else {
            return Ok(());
        };
        match value {
            '|' => {
                self.cursor.bump();
                self.emit(TokenKind::Alternation, start)
            }
            '.' => {
                self.cursor.bump();
                self.emit(TokenKind::Dot, start)
            }
            '(' => self.lex_group_open(start),
            ')' => {
                self.cursor.bump();
                self.emit(TokenKind::GroupClose, start)?;
                self.pop_ignore_whitespace();
                Ok(())
            }
            '[' => {
                self.cursor.bump();
                self.emit(TokenKind::ClassOpen, start)?;
                self.classes.push(ClassFrame::new());
                Ok(())
            }
            '?' => {
                self.cursor.bump();
                self.emit(TokenKind::ZeroOrOne, start)
            }
            '*' => {
                self.cursor.bump();
                self.emit(TokenKind::ZeroOrMore, start)
            }
            '+' => {
                self.cursor.bump();
                self.emit(TokenKind::OneOrMore, start)
            }
            '{' => self.lex_counted_repetition(start),
            '^' => {
                self.cursor.bump();
                self.emit(TokenKind::LineStart, start)
            }
            '$' => {
                self.cursor.bump();
                self.emit(TokenKind::LineEnd, start)
            }
            '\\' => self.lex_escape(start, false),
            _ => {
                self.cursor.bump();
                self.emit(TokenKind::Literal(value), start)
            }
        }
    }

    fn lex_class(&mut self) -> Result<(), LexError> {
        let start = self.cursor.mark();
        let Some(value) = self.cursor.peek() else {
            return Ok(());
        };
        match value {
            '[' if self.cursor.starts_with("[:") => {
                self.lex_posix_class(start)?;
                self.mark_class_atom();
                Ok(())
            }
            '[' => {
                self.cursor.bump();
                self.emit(TokenKind::ClassOpen, start)?;
                self.mark_class_atom();
                self.classes.push(ClassFrame::new());
                Ok(())
            }
            ']' if self.classes.last().is_some_and(|frame| frame.first_atom) => {
                self.cursor.bump();
                self.emit(TokenKind::Literal(']'), start)?;
                self.mark_class_atom();
                Ok(())
            }
            ']' => {
                self.cursor.bump();
                self.emit(TokenKind::ClassClose, start)?;
                self.classes.pop();
                Ok(())
            }
            '^' if self
                .classes
                .last()
                .is_some_and(|frame| frame.negation_allowed) =>
            {
                self.cursor.bump();
                self.emit(TokenKind::ClassNegation, start)?;
                if let Some(frame) = self.classes.last_mut() {
                    frame.negation_allowed = false;
                }
                Ok(())
            }
            '&' if self.cursor.starts_with("&&") => {
                self.cursor.consume("&&");
                self.emit(TokenKind::ClassIntersection, start)
            }
            '-' if self.cursor.starts_with("--") => {
                self.cursor.consume("--");
                self.emit(TokenKind::ClassDifference, start)
            }
            '~' if self.cursor.starts_with("~~") => {
                self.cursor.consume("~~");
                self.emit(TokenKind::ClassSymmetricDifference, start)
            }
            '-' => {
                self.cursor.bump();
                self.emit(TokenKind::ClassRange, start)
            }
            '\\' => {
                self.lex_escape(start, true)?;
                self.mark_class_atom();
                Ok(())
            }
            _ => {
                self.cursor.bump();
                self.emit(TokenKind::Literal(value), start)?;
                self.mark_class_atom();
                Ok(())
            }
        }
    }

    fn lex_group_open(&mut self, start: Mark) -> Result<(), LexError> {
        self.cursor.bump();
        self.skip_ignored();
        if !self.cursor.consume("?") {
            self.emit(TokenKind::GroupOpen, start)?;
            self.push_ignore_whitespace(self.ignores_whitespace());
            return Ok(());
        }

        self.skip_ignored();
        if self.cursor.consume("=") || self.cursor.consume("!") {
            return Err(self.error(LexErrorKind::UnsupportedLookaround, start));
        }
        if self.cursor.starts_with("<=") || self.cursor.starts_with("<!") {
            self.cursor.bump();
            self.cursor.bump();
            return Err(self.error(LexErrorKind::UnsupportedLookaround, start));
        }
        if self.cursor.consume(":") {
            self.emit(TokenKind::NonCapturingGroupOpen, start)?;
            self.push_ignore_whitespace(self.ignores_whitespace());
            return Ok(());
        }
        if self.cursor.consume("P<") {
            return self.lex_named_capture(start, NamedCaptureStyle::Python);
        }
        if self.cursor.consume("<") {
            return self.lex_named_capture(start, NamedCaptureStyle::Angle);
        }
        self.lex_flags(start)
    }

    fn lex_named_capture(&mut self, start: Mark, style: NamedCaptureStyle) -> Result<(), LexError> {
        let name_start = self.cursor.mark();
        let Some(first) = self.cursor.peek() else {
            return Err(self.error(LexErrorKind::MalformedGroupPrefix, start));
        };
        if first != '_' && !first.is_alphabetic() {
            self.cursor.bump();
            return Err(self.error(LexErrorKind::MalformedGroupPrefix, name_start));
        }
        self.cursor.bump();
        while self
            .cursor
            .peek()
            .is_some_and(|value| value == '_' || value.is_alphanumeric())
        {
            self.cursor.bump();
        }
        let name = self.cursor.span_from(name_start);
        if !self.cursor.consume(">") {
            return Err(self.error(LexErrorKind::MalformedGroupPrefix, start));
        }
        self.emit(TokenKind::NamedCaptureGroupOpen { style, name }, start)?;
        self.push_ignore_whitespace(self.ignores_whitespace());
        Ok(())
    }

    fn lex_flags(&mut self, start: Mark) -> Result<(), LexError> {
        let mut set = FlagSet::default();
        let mut clear = FlagSet::default();
        let mut clearing = false;
        let mut saw_set = false;
        let mut saw_clear = false;

        loop {
            let current = self.cursor.mark();
            self.skip_ignored();
            let Some(value) = self.cursor.peek() else {
                return Err(self.error(LexErrorKind::InvalidFlag, start));
            };
            if value == ':' || value == ')' {
                if !saw_set && !saw_clear {
                    return Err(self.error(LexErrorKind::InvalidFlag, start));
                }
                self.cursor.bump();
                self.emit(
                    TokenKind::FlagDirective {
                        set,
                        clear,
                        scoped: value == ':',
                    },
                    start,
                )?;
                let enabled = if set.contains(Flag::IgnoreWhitespace) {
                    true
                } else if clear.contains(Flag::IgnoreWhitespace) {
                    false
                } else {
                    self.ignores_whitespace()
                };
                if value == ':' {
                    self.push_ignore_whitespace(enabled);
                } else {
                    self.set_ignore_whitespace(enabled);
                }
                return Ok(());
            }
            if value == '-' {
                self.cursor.bump();
                if clearing {
                    return Err(self.error(LexErrorKind::InvalidFlag, current));
                }
                clearing = true;
                continue;
            }
            let Some(flag) = Flag::from_char(value) else {
                self.cursor.bump();
                return Err(self.error(LexErrorKind::InvalidFlag, current));
            };
            self.cursor.bump();
            if clearing {
                clear.insert(flag);
                saw_clear = true;
            } else {
                set.insert(flag);
                saw_set = true;
            }
        }
    }

    fn lex_counted_repetition(&mut self, start: Mark) -> Result<(), LexError> {
        self.cursor.bump();
        self.skip_ignored();
        let min = self.lex_decimal(start)?;
        self.skip_ignored();
        if self.cursor.consume("}") {
            return self.emit(TokenKind::Counted(RepetitionRange::Exact(min)), start);
        }
        if !self.cursor.consume(",") {
            return Err(self.error(LexErrorKind::InvalidRepetition, start));
        }
        self.skip_ignored();
        if self.cursor.consume("}") {
            return self.emit(TokenKind::Counted(RepetitionRange::AtLeast(min)), start);
        }
        let max = self.lex_decimal(start)?;
        self.skip_ignored();
        if !self.cursor.consume("}") || min > max {
            return Err(self.error(LexErrorKind::InvalidRepetition, start));
        }
        self.emit(
            TokenKind::Counted(RepetitionRange::Bounded { min, max }),
            start,
        )
    }

    fn lex_decimal(&mut self, repetition_start: Mark) -> Result<u32, LexError> {
        let mut value = 0_u32;
        let mut digits = 0_usize;
        loop {
            self.skip_ignored();
            let Some(current) = self.cursor.peek() else {
                break;
            };
            let Some(digit) = current.to_digit(10) else {
                break;
            };
            self.cursor.bump();
            value = value
                .checked_mul(10)
                .and_then(|number| number.checked_add(digit))
                .ok_or_else(|| self.error(LexErrorKind::InvalidRepetition, repetition_start))?;
            digits = digits.saturating_add(1);
        }
        if digits == 0 {
            return Err(self.error(LexErrorKind::InvalidRepetition, repetition_start));
        }
        Ok(value)
    }

    fn lex_escape(&mut self, start: Mark, in_class: bool) -> Result<(), LexError> {
        self.cursor.bump();
        let Some(value) = self.cursor.bump() else {
            return Err(self.error(LexErrorKind::TrailingEscape, start));
        };
        let escape = match value {
            'a' => Escape::Control('\u{7}'),
            'f' => Escape::Control('\u{c}'),
            't' => Escape::Control('\t'),
            'n' => Escape::Control('\n'),
            'r' => Escape::Control('\r'),
            'v' => Escape::Control('\u{b}'),
            'x' => {
                self.skip_ignored();
                if self.cursor.consume("{") {
                    Escape::Hex(self.lex_braced_hex(start)?)
                } else {
                    Escape::Hex(self.lex_fixed_hex(start, 2)?)
                }
            }
            'u' => Escape::Unicode(self.lex_unicode_escape(start)?),
            'd' => Escape::PerlClass(PerlClass::Digit),
            'D' => Escape::PerlClass(PerlClass::NotDigit),
            's' => Escape::PerlClass(PerlClass::Space),
            'S' => Escape::PerlClass(PerlClass::NotSpace),
            'w' => Escape::PerlClass(PerlClass::Word),
            'W' => Escape::PerlClass(PerlClass::NotWord),
            'p' | 'P' => self.lex_unicode_class(start, value == 'P')?,
            'A' => Escape::Assertion(Assertion::TextStart),
            'z' => Escape::Assertion(Assertion::TextEnd),
            'B' => Escape::Assertion(Assertion::NotWordBoundary),
            '<' => Escape::Assertion(Assertion::AsciiWordStart),
            '>' => Escape::Assertion(Assertion::AsciiWordEnd),
            'b' if in_class => Escape::Control('\u{8}'),
            'b' => self.lex_word_boundary(start)?,
            '0'..='9' => {
                return Err(self.error(LexErrorKind::UnsupportedBackreference, start));
            }
            'k' if self.cursor.starts_with("<") || self.cursor.starts_with("'") => {
                return Err(self.error(LexErrorKind::UnsupportedBackreference, start));
            }
            escaped if escaped.is_ascii_punctuation() || escaped.is_ascii_whitespace() => {
                Escape::Literal(escaped)
            }
            _ => return Err(self.error(LexErrorKind::MalformedEscape, start)),
        };
        self.emit(TokenKind::Escaped(escape), start)
    }

    fn lex_fixed_hex(&mut self, start: Mark, digits: usize) -> Result<char, LexError> {
        let mut value = 0_u32;
        for _ in 0..digits {
            self.skip_ignored();
            let Some(current) = self.cursor.peek() else {
                return Err(self.error(LexErrorKind::MalformedEscape, start));
            };
            let Some(digit) = current.to_digit(16) else {
                self.cursor.bump();
                return Err(self.error(LexErrorKind::MalformedEscape, start));
            };
            self.cursor.bump();
            value = value.saturating_mul(16).saturating_add(digit);
        }
        char::from_u32(value).ok_or_else(|| self.error(LexErrorKind::InvalidUnicodeScalar, start))
    }

    fn lex_unicode_escape(&mut self, start: Mark) -> Result<char, LexError> {
        self.skip_ignored();
        if !self.cursor.consume("{") {
            return Err(self.error(LexErrorKind::MalformedEscape, start));
        }
        self.lex_braced_hex(start)
    }

    fn lex_braced_hex(&mut self, start: Mark) -> Result<char, LexError> {
        let mut value = 0_u32;
        let mut digits = 0_usize;
        loop {
            self.skip_ignored();
            let Some(current) = self.cursor.peek() else {
                break;
            };
            let Some(digit) = current.to_digit(16) else {
                break;
            };
            if digits == 6 {
                self.cursor.bump();
                return Err(self.error(LexErrorKind::InvalidUnicodeScalar, start));
            }
            self.cursor.bump();
            value = value.saturating_mul(16).saturating_add(digit);
            digits = digits.saturating_add(1);
        }
        self.skip_ignored();
        if digits == 0 || !self.cursor.consume("}") {
            return Err(self.error(LexErrorKind::MalformedEscape, start));
        }
        char::from_u32(value).ok_or_else(|| self.error(LexErrorKind::InvalidUnicodeScalar, start))
    }

    fn lex_unicode_class(&mut self, start: Mark, negated: bool) -> Result<Escape, LexError> {
        self.skip_ignored();
        let name_start;
        let name;
        if self.cursor.consume("{") {
            self.skip_ignored();
            name_start = self.cursor.mark();
            while self.cursor.peek().is_some_and(is_property_name_char) {
                self.cursor.bump();
            }
            name = self.cursor.span_from(name_start);
            self.skip_ignored();
            if name.byte_start == name.byte_end || !self.cursor.consume("}") {
                return Err(self.error(LexErrorKind::MalformedEscape, start));
            }
        } else {
            name_start = self.cursor.mark();
            let Some(value) = self.cursor.peek() else {
                return Err(self.error(LexErrorKind::MalformedEscape, start));
            };
            if !value.is_alphabetic() {
                self.cursor.bump();
                return Err(self.error(LexErrorKind::MalformedEscape, start));
            }
            self.cursor.bump();
            name = self.cursor.span_from(name_start);
        }
        Ok(Escape::UnicodeClass { negated, name })
    }

    fn lex_word_boundary(&mut self, start: Mark) -> Result<Escape, LexError> {
        if !self.cursor.consume("{") {
            return Ok(Escape::Assertion(Assertion::WordBoundary));
        }
        let name_start = self.cursor.mark();
        while self
            .cursor
            .peek()
            .is_some_and(|value| value.is_ascii_lowercase() || value == '-')
        {
            self.cursor.bump();
        }
        let name = self.cursor.span_from(name_start);
        if !self.cursor.consume("}") {
            return Err(self.error(LexErrorKind::MalformedEscape, start));
        }
        let Some(value) = name.source(self.cursor.source) else {
            return Err(self.error(LexErrorKind::MalformedEscape, start));
        };
        let assertion = match value {
            "start" => Assertion::WordStart,
            "end" => Assertion::WordEnd,
            "start-half" => Assertion::WordStartHalf,
            "end-half" => Assertion::WordEndHalf,
            _ => return Err(self.error(LexErrorKind::MalformedEscape, start)),
        };
        Ok(Escape::Assertion(assertion))
    }

    fn lex_posix_class(&mut self, start: Mark) -> Result<(), LexError> {
        self.cursor.consume("[:");
        let negated = self.cursor.consume("^");
        let name_start = self.cursor.mark();
        while self
            .cursor
            .peek()
            .is_some_and(|value| value.is_ascii_alphabetic())
        {
            self.cursor.bump();
        }
        let name = self.cursor.span_from(name_start);
        if name.byte_start == name.byte_end || !self.cursor.consume(":]") {
            return Err(self.error(LexErrorKind::MalformedEscape, start));
        }
        self.emit(TokenKind::PosixClass { negated, name }, start)
    }
}

fn is_property_name_char(value: char) -> bool {
    value.is_alphanumeric() || matches!(value, '_' | '-' | '=' | ':')
}

pub fn lex(pattern: &str, limits: LexerLimits) -> Result<Vec<Token>, LexError> {
    if pattern.len() > limits.max_pattern_bytes {
        return Err(LexError {
            kind: LexErrorKind::PatternTooLarge,
            span: SourceSpan {
                byte_start: 0,
                byte_end: pattern.len(),
                scalar_start: 0,
                scalar_end: pattern.chars().count(),
            },
        });
    }
    Lexer::new(pattern, limits).run()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserLimits {
    pub max_ast_nodes: usize,
    pub max_nesting: usize,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self {
            max_ast_nodes: DEFAULT_MAX_AST_NODES,
            max_nesting: DEFAULT_MAX_NESTING,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeId(usize);

impl NodeId {
    pub const fn index(self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantifier {
    ZeroOrOne,
    ZeroOrMore,
    OneOrMore,
    Counted(RepetitionRange),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Greediness {
    Greedy,
    Lazy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassSetOperator {
    Intersection,
    Difference,
    SymmetricDifference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstNodeKind {
    Empty,
    Literal(char),
    Dot,
    Escape(Escape),
    Assertion(Assertion),
    LineStart,
    LineEnd,
    Concat(Vec<NodeId>),
    Alternation(Vec<NodeId>),
    Capture {
        index: usize,
        name: Option<SourceSpan>,
        style: Option<NamedCaptureStyle>,
        child: NodeId,
    },
    NonCapturing {
        child: NodeId,
    },
    Flags {
        set: FlagSet,
        clear: FlagSet,
        scoped: bool,
        child: Option<NodeId>,
    },
    Repetition {
        child: NodeId,
        quantifier: Quantifier,
        greediness: Greediness,
    },
    Class {
        negated: bool,
        expression: NodeId,
    },
    ClassLiteral(char),
    ClassEscape(Escape),
    PosixClass {
        negated: bool,
        name: SourceSpan,
    },
    ClassRange {
        start: NodeId,
        end: NodeId,
    },
    ClassUnion(Vec<NodeId>),
    ClassSet {
        operator: ClassSetOperator,
        left: NodeId,
        right: NodeId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpansionBound {
    Finite(u128),
    Unbounded,
    Overflowed,
}

impl ExpansionBound {
    fn add(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unbounded, _) | (_, Self::Unbounded) => Self::Unbounded,
            (Self::Overflowed, _) | (_, Self::Overflowed) => Self::Overflowed,
            (Self::Finite(left), Self::Finite(right)) => left
                .checked_add(right)
                .map_or(Self::Overflowed, Self::Finite),
        }
    }

    fn multiply(self, factor: u32) -> Self {
        match self {
            Self::Finite(value) => value
                .checked_mul(u128::from(factor))
                .map_or(Self::Overflowed, Self::Finite),
            Self::Unbounded => Self::Unbounded,
            Self::Overflowed => Self::Overflowed,
        }
    }

    fn minimum(self, other: Self) -> Self {
        match (self, other) {
            (Self::Finite(left), Self::Finite(right)) => Self::Finite(left.min(right)),
            (Self::Finite(value), Self::Unbounded | Self::Overflowed)
            | (Self::Unbounded | Self::Overflowed, Self::Finite(value)) => Self::Finite(value),
            (Self::Unbounded, Self::Unbounded) => Self::Unbounded,
            _ => Self::Overflowed,
        }
    }

    fn maximum(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unbounded, _) | (_, Self::Unbounded) => Self::Unbounded,
            (Self::Overflowed, _) | (_, Self::Overflowed) => Self::Overflowed,
            (Self::Finite(left), Self::Finite(right)) => Self::Finite(left.max(right)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpansionEstimate {
    pub minimum: ExpansionBound,
    pub maximum: ExpansionBound,
}

impl ExpansionEstimate {
    const ZERO: Self = Self {
        minimum: ExpansionBound::Finite(0),
        maximum: ExpansionBound::Finite(0),
    };

    const UNIT: Self = Self {
        minimum: ExpansionBound::Finite(1),
        maximum: ExpansionBound::Finite(1),
    };

    fn concatenate(self, other: Self) -> Self {
        Self {
            minimum: self.minimum.add(other.minimum),
            maximum: self.maximum.add(other.maximum),
        }
    }

    fn alternate(self, other: Self) -> Self {
        Self {
            minimum: self.minimum.minimum(other.minimum),
            maximum: self.maximum.maximum(other.maximum),
        }
    }

    fn repeat(self, quantifier: Quantifier) -> Self {
        match quantifier {
            Quantifier::ZeroOrOne => Self {
                minimum: ExpansionBound::Finite(0),
                maximum: self.maximum,
            },
            Quantifier::ZeroOrMore => Self {
                minimum: ExpansionBound::Finite(0),
                maximum: match self.maximum {
                    ExpansionBound::Finite(0) => ExpansionBound::Finite(0),
                    _ => ExpansionBound::Unbounded,
                },
            },
            Quantifier::OneOrMore => Self {
                minimum: self.minimum,
                maximum: match self.maximum {
                    ExpansionBound::Finite(0) => ExpansionBound::Finite(0),
                    _ => ExpansionBound::Unbounded,
                },
            },
            Quantifier::Counted(RepetitionRange::Exact(count)) => Self {
                minimum: self.minimum.multiply(count),
                maximum: self.maximum.multiply(count),
            },
            Quantifier::Counted(RepetitionRange::AtLeast(minimum)) => Self {
                minimum: self.minimum.multiply(minimum),
                maximum: match self.maximum {
                    ExpansionBound::Finite(0) => ExpansionBound::Finite(0),
                    _ => ExpansionBound::Unbounded,
                },
            },
            Quantifier::Counted(RepetitionRange::Bounded { min, max }) => Self {
                minimum: self.minimum.multiply(min),
                maximum: self.maximum.multiply(max),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AstNode {
    pub kind: AstNodeKind,
    pub span: SourceSpan,
    /// Bounded accounting only. Repetition is never expanded into cloned AST nodes.
    pub expansion: ExpansionEstimate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseResources {
    pub tokens_consumed: usize,
    pub ast_nodes: usize,
    pub max_nesting: usize,
    pub repetition_operators: usize,
    pub repetition_expansion: ExpansionEstimate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ast {
    pub grammar_id: &'static str,
    pub root: NodeId,
    pub nodes: Vec<AstNode>,
    pub resources: ParseResources,
}

impl Ast {
    pub fn node(&self, id: NodeId) -> Option<&AstNode> {
        self.nodes.get(id.index())
    }

    pub fn invariants_hold(&self, pattern: &str) -> bool {
        if self.grammar_id != GRAMMAR_ID
            || self.root.index() >= self.nodes.len()
            || self.resources.ast_nodes != self.nodes.len()
            || self
                .node(self.root)
                .is_none_or(|root| root.expansion != self.resources.repetition_expansion)
        {
            return false;
        }
        self.nodes.iter().enumerate().all(|(index, node)| {
            node.span.source(pattern).is_some() && children_are_prior(&node.kind, index)
        })
    }
}

fn children_are_prior(kind: &AstNodeKind, parent_index: usize) -> bool {
    let prior = |child: NodeId| child.index() < parent_index;
    match kind {
        AstNodeKind::Concat(children)
        | AstNodeKind::Alternation(children)
        | AstNodeKind::ClassUnion(children) => children.iter().copied().all(prior),
        AstNodeKind::Capture { child, .. }
        | AstNodeKind::NonCapturing { child }
        | AstNodeKind::Repetition { child, .. } => prior(*child),
        AstNodeKind::Flags {
            child: Some(child), ..
        } => prior(*child),
        AstNodeKind::Class { expression, .. } => prior(*expression),
        AstNodeKind::ClassRange { start, end } => prior(*start) && prior(*end),
        AstNodeKind::ClassSet { left, right, .. } => prior(*left) && prior(*right),
        _ => true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    AstNodeLimit,
    NestingLimit,
    UnclosedGroup,
    UnexpectedGroupClose,
    UnclosedClass,
    InvalidClassEscape,
    InvalidClassRange,
    InvalidClassOperator,
    InvalidRepetition,
    InvalidFlag,
    InvalidUtf8Invariant,
    UnexpectedToken,
    DuplicateCaptureName,
}

impl ParseErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AstNodeLimit => "RGX-PARSE-E001",
            Self::NestingLimit => "RGX-PARSE-E002",
            Self::UnclosedGroup => "RGX-PARSE-E003",
            Self::UnexpectedGroupClose => "RGX-PARSE-E004",
            Self::UnclosedClass => "RGX-PARSE-E005",
            Self::InvalidClassEscape => "RGX-PARSE-E006",
            Self::InvalidClassRange => "RGX-PARSE-E007",
            Self::InvalidClassOperator => "RGX-PARSE-E008",
            Self::InvalidRepetition => "RGX-PARSE-E009",
            Self::InvalidFlag => "RGX-PARSE-E010",
            Self::InvalidUtf8Invariant => "RGX-PARSE-E011",
            Self::UnexpectedToken => "RGX-PARSE-E012",
            Self::DuplicateCaptureName => "RGX-PARSE-E013",
        }
    }

    pub const fn diagnostic_category(self) -> &'static str {
        match self {
            Self::AstNodeLimit => "RGX-DIAG-AST-LIMIT",
            Self::NestingLimit => "RGX-DIAG-NEST-LIMIT",
            Self::UnclosedGroup | Self::UnexpectedGroupClose | Self::UnexpectedToken => {
                "RGX-DIAG-UNCLOSED-GROUP"
            }
            Self::UnclosedClass
            | Self::InvalidClassEscape
            | Self::InvalidClassRange
            | Self::InvalidClassOperator => "RGX-DIAG-UNCLOSED-CLASS",
            Self::InvalidRepetition => "RGX-DIAG-INVALID-REPETITION",
            Self::InvalidFlag => "RGX-DIAG-INVALID-FLAG",
            Self::InvalidUtf8Invariant => "RGX-DIAG-INVALID-UTF8",
            Self::DuplicateCaptureName => "RGX-DIAG-DUPLICATE-CAPTURE-NAME",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub span: SourceSpan,
}

impl fmt::Display for ParseError {
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

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntaxError {
    Lex(LexError),
    Parse(ParseError),
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lex(error) => error.fmt(formatter),
            Self::Parse(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SyntaxError {}

impl From<LexError> for SyntaxError {
    fn from(error: LexError) -> Self {
        Self::Lex(error)
    }
}

impl From<ParseError> for SyntaxError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

#[derive(Debug, Clone, Copy)]
enum GroupKind {
    Root,
    Capture {
        index: usize,
        name: Option<SourceSpan>,
        style: Option<NamedCaptureStyle>,
    },
    NonCapturing,
    Flags {
        set: FlagSet,
        clear: FlagSet,
    },
}

struct ExpressionFrame {
    kind: GroupKind,
    opener: SourceSpan,
    flags: FlagSet,
    alternatives: Vec<NodeId>,
    concatenation: Vec<NodeId>,
    empty_span: SourceSpan,
    owns_unicode_disabled_scope: bool,
    unicode_violation: bool,
}

impl ExpressionFrame {
    fn root(at: SourceSpan) -> Self {
        Self {
            kind: GroupKind::Root,
            opener: at,
            flags: FlagSet::regex_default(),
            alternatives: Vec::new(),
            concatenation: Vec::new(),
            empty_span: at,
            owns_unicode_disabled_scope: false,
            unicode_violation: false,
        }
    }

    fn group(
        kind: GroupKind,
        opener: SourceSpan,
        flags: FlagSet,
        owns_unicode_disabled_scope: bool,
    ) -> Self {
        Self {
            kind,
            opener,
            flags,
            alternatives: Vec::new(),
            concatenation: Vec::new(),
            empty_span: SourceSpan::empty_at(opener.byte_end, opener.scalar_end),
            owns_unicode_disabled_scope,
            unicode_violation: false,
        }
    }
}

struct PendingRange {
    left: NodeId,
    operator_span: SourceSpan,
}

struct ClassParseFrame {
    opener: SourceSpan,
    negated: bool,
    at_start: bool,
    union: Vec<NodeId>,
    left: Option<NodeId>,
    pending_operator: Option<(ClassSetOperator, SourceSpan)>,
    pending_range: Option<PendingRange>,
}

impl ClassParseFrame {
    fn new(opener: SourceSpan) -> Self {
        Self {
            opener,
            negated: false,
            at_start: true,
            union: Vec::new(),
            left: None,
            pending_operator: None,
            pending_range: None,
        }
    }
}

struct Parser<'source> {
    pattern: &'source str,
    tokens: Vec<Token>,
    index: usize,
    limits: ParserLimits,
    nodes: Vec<AstNode>,
    nesting: usize,
    max_nesting: usize,
    repetition_operators: usize,
    next_capture: usize,
    named_captures: BTreeMap<&'source str, SourceSpan>,
}

impl<'source> Parser<'source> {
    fn new(pattern: &'source str, tokens: Vec<Token>, limits: ParserLimits) -> Self {
        let initial_capacity = tokens.len().min(limits.max_ast_nodes).min(4_096);
        Self {
            pattern,
            tokens,
            index: 0,
            limits,
            nodes: Vec::with_capacity(initial_capacity),
            nesting: 0,
            max_nesting: 0,
            repetition_operators: 0,
            next_capture: 1,
            named_captures: BTreeMap::new(),
        }
    }

    fn run(mut self) -> Result<Ast, ParseError> {
        let start = self
            .tokens
            .first()
            .map_or(SourceSpan::empty_at(0, 0), |token| {
                SourceSpan::empty_at(token.span.byte_start, token.span.scalar_start)
            });
        let mut frames = vec![ExpressionFrame::root(start)];
        loop {
            let token = self.current()?;
            match token.kind {
                TokenKind::End => {
                    if frames.len() != 1 {
                        let unclosed = frames.last().map_or(token.span, |frame| frame.opener);
                        return Err(self.error(ParseErrorKind::UnclosedGroup, unclosed));
                    }
                    let frame = frames
                        .pop()
                        .ok_or_else(|| self.error(ParseErrorKind::UnexpectedToken, token.span))?;
                    let root = self.finish_expression(frame)?;
                    if self.index + 1 != self.tokens.len() {
                        return Err(self.error(ParseErrorKind::UnexpectedToken, token.span));
                    }
                    let expansion = self.expansion(root)?;
                    let resources = ParseResources {
                        tokens_consumed: self.tokens.len(),
                        ast_nodes: self.nodes.len(),
                        max_nesting: self.max_nesting,
                        repetition_operators: self.repetition_operators,
                        repetition_expansion: expansion,
                    };
                    return Ok(Ast {
                        grammar_id: GRAMMAR_ID,
                        root,
                        nodes: self.nodes,
                        resources,
                    });
                }
                TokenKind::Alternation => {
                    self.finish_alternative(&mut frames, token.span)?;
                    self.index += 1;
                }
                TokenKind::GroupOpen => {
                    let capture = self.next_capture;
                    self.next_capture = self.next_capture.saturating_add(1);
                    self.open_group(
                        &mut frames,
                        GroupKind::Capture {
                            index: capture,
                            name: None,
                            style: None,
                        },
                        token.span,
                        None,
                    )?;
                    self.index += 1;
                }
                TokenKind::NamedCaptureGroupOpen { style, name } => {
                    let capture_name = name
                        .source(self.pattern)
                        .ok_or_else(|| self.error(ParseErrorKind::UnexpectedToken, name))?;
                    if self.named_captures.insert(capture_name, name).is_some() {
                        return Err(self.error(ParseErrorKind::DuplicateCaptureName, name));
                    }
                    let capture = self.next_capture;
                    self.next_capture = self.next_capture.saturating_add(1);
                    self.open_group(
                        &mut frames,
                        GroupKind::Capture {
                            index: capture,
                            name: Some(name),
                            style: Some(style),
                        },
                        token.span,
                        None,
                    )?;
                    self.index += 1;
                }
                TokenKind::NonCapturingGroupOpen => {
                    self.open_group(&mut frames, GroupKind::NonCapturing, token.span, None)?;
                    self.index += 1;
                }
                TokenKind::FlagDirective { set, clear, scoped } => {
                    if set.intersects(clear) {
                        return Err(self.error(ParseErrorKind::InvalidFlag, token.span));
                    }
                    if scoped {
                        self.open_group(
                            &mut frames,
                            GroupKind::Flags { set, clear },
                            token.span,
                            Some((set, clear)),
                        )?;
                    } else {
                        self.apply_global_flags(&mut frames, set, clear, token.span)?;
                    }
                    self.index += 1;
                }
                TokenKind::GroupClose => {
                    self.close_group(&mut frames, token.span)?;
                    self.index += 1;
                }
                TokenKind::ClassOpen => {
                    let class = self.parse_class()?;
                    self.append_atom(&mut frames, class, false)?;
                }
                TokenKind::ZeroOrOne
                | TokenKind::ZeroOrMore
                | TokenKind::OneOrMore
                | TokenKind::Counted(_) => {
                    self.apply_repetition(&mut frames)?;
                }
                TokenKind::Literal(value) => {
                    let node = self.push_node(
                        AstNodeKind::Literal(value),
                        token.span,
                        ExpansionEstimate::UNIT,
                    )?;
                    self.append_atom(&mut frames, node, false)?;
                    self.index += 1;
                }
                TokenKind::Dot => {
                    let node =
                        self.push_node(AstNodeKind::Dot, token.span, ExpansionEstimate::UNIT)?;
                    self.append_atom(&mut frames, node, true)?;
                    self.index += 1;
                }
                TokenKind::LineStart => {
                    let node = self.push_node(
                        AstNodeKind::LineStart,
                        token.span,
                        ExpansionEstimate::ZERO,
                    )?;
                    self.append_atom(&mut frames, node, false)?;
                    self.index += 1;
                }
                TokenKind::LineEnd => {
                    let node =
                        self.push_node(AstNodeKind::LineEnd, token.span, ExpansionEstimate::ZERO)?;
                    self.append_atom(&mut frames, node, false)?;
                    self.index += 1;
                }
                TokenKind::Escaped(Escape::Assertion(assertion)) => {
                    let node = self.push_node(
                        AstNodeKind::Assertion(assertion),
                        token.span,
                        ExpansionEstimate::ZERO,
                    )?;
                    self.append_atom(&mut frames, node, false)?;
                    self.index += 1;
                }
                TokenKind::Escaped(escape) => {
                    let node = self.push_node(
                        AstNodeKind::Escape(escape),
                        token.span,
                        ExpansionEstimate::UNIT,
                    )?;
                    self.append_atom(&mut frames, node, false)?;
                    self.index += 1;
                }
                TokenKind::ClassClose
                | TokenKind::ClassNegation
                | TokenKind::ClassRange
                | TokenKind::ClassIntersection
                | TokenKind::ClassDifference
                | TokenKind::ClassSymmetricDifference
                | TokenKind::PosixClass { .. } => {
                    return Err(self.error(ParseErrorKind::UnexpectedToken, token.span));
                }
            }
        }
    }

    fn current(&self) -> Result<Token, ParseError> {
        self.tokens.get(self.index).copied().ok_or_else(|| {
            let span = self
                .tokens
                .last()
                .map_or(SourceSpan::empty_at(0, 0), |token| token.span);
            self.error(ParseErrorKind::UnexpectedToken, span)
        })
    }

    const fn error(&self, kind: ParseErrorKind, span: SourceSpan) -> ParseError {
        ParseError { kind, span }
    }

    fn enter_nesting(&mut self, span: SourceSpan) -> Result<(), ParseError> {
        if self.nesting >= self.limits.max_nesting {
            return Err(self.error(ParseErrorKind::NestingLimit, span));
        }
        self.nesting += 1;
        self.max_nesting = self.max_nesting.max(self.nesting);
        Ok(())
    }

    fn leave_nesting(&mut self) {
        self.nesting = self.nesting.saturating_sub(1);
    }

    fn push_node(
        &mut self,
        kind: AstNodeKind,
        span: SourceSpan,
        expansion: ExpansionEstimate,
    ) -> Result<NodeId, ParseError> {
        if self.nodes.len() >= self.limits.max_ast_nodes {
            return Err(self.error(ParseErrorKind::AstNodeLimit, span));
        }
        let id = NodeId(self.nodes.len());
        self.nodes.push(AstNode {
            kind,
            span,
            expansion,
        });
        Ok(id)
    }

    fn expansion(&self, id: NodeId) -> Result<ExpansionEstimate, ParseError> {
        self.nodes
            .get(id.index())
            .map(|node| node.expansion)
            .ok_or_else(|| self.error(ParseErrorKind::UnexpectedToken, SourceSpan::empty_at(0, 0)))
    }

    fn open_group(
        &mut self,
        frames: &mut Vec<ExpressionFrame>,
        kind: GroupKind,
        opener: SourceSpan,
        flag_delta: Option<(FlagSet, FlagSet)>,
    ) -> Result<(), ParseError> {
        self.enter_nesting(opener)?;
        let parent_flags = frames
            .last()
            .map_or_else(FlagSet::regex_default, |frame| frame.flags);
        let flags = flag_delta.map_or(parent_flags, |(set, clear)| parent_flags.apply(set, clear));
        let owns_unicode_disabled_scope =
            parent_flags.contains(Flag::Unicode) && !flags.contains(Flag::Unicode);
        frames.push(ExpressionFrame::group(
            kind,
            opener,
            flags,
            owns_unicode_disabled_scope,
        ));
        Ok(())
    }

    fn apply_global_flags(
        &mut self,
        frames: &mut [ExpressionFrame],
        set: FlagSet,
        clear: FlagSet,
        span: SourceSpan,
    ) -> Result<(), ParseError> {
        let node = self.push_node(
            AstNodeKind::Flags {
                set,
                clear,
                scoped: false,
                child: None,
            },
            span,
            ExpansionEstimate::ZERO,
        )?;
        let Some(frame) = frames.last_mut() else {
            return Err(self.error(ParseErrorKind::UnexpectedToken, span));
        };
        frame.flags = frame.flags.apply(set, clear);
        frame.concatenation.push(node);
        Ok(())
    }

    fn append_atom(
        &self,
        frames: &mut [ExpressionFrame],
        node: NodeId,
        requires_unicode: bool,
    ) -> Result<(), ParseError> {
        let Some(current) = frames.last() else {
            let span = self
                .nodes
                .get(node.index())
                .map_or(SourceSpan::empty_at(0, 0), |entry| entry.span);
            return Err(self.error(ParseErrorKind::UnexpectedToken, span));
        };
        if requires_unicode && !current.flags.contains(Flag::Unicode) {
            if let Some(owner) = frames
                .iter_mut()
                .rev()
                .find(|frame| frame.owns_unicode_disabled_scope)
            {
                owner.unicode_violation = true;
            } else {
                let span = self
                    .nodes
                    .get(node.index())
                    .map_or(SourceSpan::empty_at(0, 0), |entry| entry.span);
                return Err(self.error(ParseErrorKind::InvalidUtf8Invariant, span));
            }
        }
        let Some(frame) = frames.last_mut() else {
            return Err(self.error(ParseErrorKind::UnexpectedToken, SourceSpan::empty_at(0, 0)));
        };
        frame.concatenation.push(node);
        Ok(())
    }

    fn finish_alternative(
        &mut self,
        frames: &mut [ExpressionFrame],
        separator: SourceSpan,
    ) -> Result<(), ParseError> {
        let Some(frame) = frames.last_mut() else {
            return Err(self.error(ParseErrorKind::UnexpectedToken, separator));
        };
        let children = core::mem::take(&mut frame.concatenation);
        let branch = self.finish_concatenation(children, frame.empty_span)?;
        frame.alternatives.push(branch);
        frame.empty_span = SourceSpan::empty_at(separator.byte_end, separator.scalar_end);
        Ok(())
    }

    fn finish_expression(&mut self, frame: ExpressionFrame) -> Result<NodeId, ParseError> {
        let last = self.finish_concatenation(frame.concatenation, frame.empty_span)?;
        if frame.alternatives.is_empty() {
            return Ok(last);
        }
        let mut alternatives = frame.alternatives;
        alternatives.push(last);
        let span = self.sequence_span(&alternatives)?;
        let expansion = self.sequence_expansion(&alternatives, false)?;
        self.push_node(AstNodeKind::Alternation(alternatives), span, expansion)
    }

    fn finish_concatenation(
        &mut self,
        children: Vec<NodeId>,
        empty_span: SourceSpan,
    ) -> Result<NodeId, ParseError> {
        match children.as_slice() {
            [] => self.push_node(AstNodeKind::Empty, empty_span, ExpansionEstimate::ZERO),
            [only] => Ok(*only),
            _ => {
                let span = self.sequence_span(&children)?;
                let expansion = self.sequence_expansion(&children, true)?;
                self.push_node(AstNodeKind::Concat(children), span, expansion)
            }
        }
    }

    fn sequence_span(&self, children: &[NodeId]) -> Result<SourceSpan, ParseError> {
        let Some(first) = children.first().and_then(|id| self.nodes.get(id.index())) else {
            return Err(self.error(ParseErrorKind::UnexpectedToken, SourceSpan::empty_at(0, 0)));
        };
        let Some(last) = children.last().and_then(|id| self.nodes.get(id.index())) else {
            return Err(self.error(ParseErrorKind::UnexpectedToken, first.span));
        };
        Ok(first.span.cover(last.span))
    }

    fn sequence_expansion(
        &self,
        children: &[NodeId],
        concatenate: bool,
    ) -> Result<ExpansionEstimate, ParseError> {
        let mut iter = children.iter().copied();
        let Some(first) = iter.next() else {
            return Ok(ExpansionEstimate::ZERO);
        };
        let mut total = self.expansion(first)?;
        for child in iter {
            let expansion = self.expansion(child)?;
            total = if concatenate {
                total.concatenate(expansion)
            } else {
                total.alternate(expansion)
            };
        }
        Ok(total)
    }

    fn close_group(
        &mut self,
        frames: &mut Vec<ExpressionFrame>,
        close: SourceSpan,
    ) -> Result<(), ParseError> {
        if frames.len() == 1 {
            return Err(self.error(ParseErrorKind::UnexpectedGroupClose, close));
        }
        let frame = frames
            .pop()
            .ok_or_else(|| self.error(ParseErrorKind::UnexpectedGroupClose, close))?;
        self.leave_nesting();
        let kind = frame.kind;
        let opener = frame.opener;
        let owns_unicode_disabled_scope = frame.owns_unicode_disabled_scope;
        let unicode_violation = frame.unicode_violation;
        let child = self.finish_expression(frame)?;
        let span = opener.cover(close);
        if owns_unicode_disabled_scope && unicode_violation {
            return Err(self.error(ParseErrorKind::InvalidUtf8Invariant, span));
        }
        let expansion = self.expansion(child)?;
        let wrapper = match kind {
            GroupKind::Root => {
                return Err(self.error(ParseErrorKind::UnexpectedGroupClose, close));
            }
            GroupKind::Capture { index, name, style } => AstNodeKind::Capture {
                index,
                name,
                style,
                child,
            },
            GroupKind::NonCapturing => AstNodeKind::NonCapturing { child },
            GroupKind::Flags { set, clear } => AstNodeKind::Flags {
                set,
                clear,
                scoped: true,
                child: Some(child),
            },
        };
        let node = self.push_node(wrapper, span, expansion)?;
        self.append_atom(frames, node, false)
    }

    fn apply_repetition(&mut self, frames: &mut [ExpressionFrame]) -> Result<(), ParseError> {
        let token = self.current()?;
        let quantifier = match token.kind {
            TokenKind::ZeroOrOne => Quantifier::ZeroOrOne,
            TokenKind::ZeroOrMore => Quantifier::ZeroOrMore,
            TokenKind::OneOrMore => Quantifier::OneOrMore,
            TokenKind::Counted(range) => Quantifier::Counted(range),
            _ => return Err(self.error(ParseErrorKind::InvalidRepetition, token.span)),
        };
        let Some(frame) = frames.last_mut() else {
            return Err(self.error(ParseErrorKind::InvalidRepetition, token.span));
        };
        let Some(child) = frame.concatenation.pop() else {
            return Err(self.error(
                ParseErrorKind::InvalidRepetition,
                SourceSpan::empty_at(token.span.byte_start, token.span.scalar_start),
            ));
        };
        if self.nodes.get(child.index()).is_some_and(|node| {
            matches!(
                node.kind,
                AstNodeKind::Flags {
                    scoped: false,
                    child: None,
                    ..
                }
            )
        }) {
            return Err(self.error(
                ParseErrorKind::InvalidRepetition,
                SourceSpan::empty_at(token.span.byte_start, token.span.scalar_start),
            ));
        }
        let mut span = self
            .nodes
            .get(child.index())
            .map_or(token.span, |node| node.span.cover(token.span));
        self.index += 1;
        let explicit_suffix = self
            .tokens
            .get(self.index)
            .is_some_and(|next| next.kind == TokenKind::ZeroOrOne);
        if explicit_suffix {
            if let Some(suffix) = self.tokens.get(self.index) {
                span = span.cover(suffix.span);
            }
            self.index += 1;
        }
        let swapped = frame.flags.contains(Flag::SwapGreed);
        let greediness = if explicit_suffix ^ swapped {
            Greediness::Lazy
        } else {
            Greediness::Greedy
        };
        let expansion = self.expansion(child)?.repeat(quantifier);
        let node = self.push_node(
            AstNodeKind::Repetition {
                child,
                quantifier,
                greediness,
            },
            span,
            expansion,
        )?;
        self.repetition_operators = self.repetition_operators.saturating_add(1);
        let Some(frame) = frames.last_mut() else {
            return Err(self.error(ParseErrorKind::InvalidRepetition, token.span));
        };
        frame.concatenation.push(node);
        Ok(())
    }

    fn parse_class(&mut self) -> Result<NodeId, ParseError> {
        let open = self.current()?;
        self.enter_nesting(open.span)?;
        let mut frames = vec![ClassParseFrame::new(open.span)];
        self.index += 1;
        loop {
            let token = self.current()?;
            match token.kind {
                TokenKind::ClassNegation => {
                    let Some(frame) = frames.last_mut() else {
                        return Err(self.error(ParseErrorKind::UnexpectedToken, token.span));
                    };
                    if !frame.at_start {
                        return Err(self.error(ParseErrorKind::UnexpectedToken, token.span));
                    }
                    frame.negated = true;
                    frame.at_start = false;
                    self.index += 1;
                }
                TokenKind::ClassOpen => {
                    self.enter_nesting(token.span)?;
                    frames.push(ClassParseFrame::new(token.span));
                    self.index += 1;
                }
                TokenKind::ClassClose => {
                    let frame = frames
                        .pop()
                        .ok_or_else(|| self.error(ParseErrorKind::UnexpectedToken, token.span))?;
                    self.leave_nesting();
                    let opener = frame.opener;
                    let negated = frame.negated;
                    let expression = self.finish_class_expression(frame, token.span)?;
                    let node = self.push_node(
                        AstNodeKind::Class {
                            negated,
                            expression,
                        },
                        opener.cover(token.span),
                        ExpansionEstimate::UNIT,
                    )?;
                    self.index += 1;
                    if frames.is_empty() {
                        return Ok(node);
                    }
                    self.append_class_atom(&mut frames, node, token.span)?;
                }
                TokenKind::ClassIntersection
                | TokenKind::ClassDifference
                | TokenKind::ClassSymmetricDifference => {
                    let operator = match token.kind {
                        TokenKind::ClassIntersection => ClassSetOperator::Intersection,
                        TokenKind::ClassDifference => ClassSetOperator::Difference,
                        TokenKind::ClassSymmetricDifference => {
                            ClassSetOperator::SymmetricDifference
                        }
                        _ => {
                            return Err(
                                self.error(ParseErrorKind::InvalidClassOperator, token.span)
                            );
                        }
                    };
                    self.begin_class_operator(&mut frames, operator, token.span)?;
                    self.index += 1;
                }
                TokenKind::ClassRange => {
                    self.handle_class_range(&mut frames, token.span)?;
                    self.index += 1;
                }
                TokenKind::Literal(value) => {
                    let atom = self.push_node(
                        AstNodeKind::ClassLiteral(value),
                        token.span,
                        ExpansionEstimate::UNIT,
                    )?;
                    self.append_class_atom(&mut frames, atom, token.span)?;
                    self.index += 1;
                }
                TokenKind::Escaped(escape) => {
                    if matches!(escape, Escape::Assertion(_) | Escape::Control('\u{8}')) {
                        return Err(self.error(ParseErrorKind::InvalidClassEscape, token.span));
                    }
                    let atom = self.push_node(
                        AstNodeKind::ClassEscape(escape),
                        token.span,
                        ExpansionEstimate::UNIT,
                    )?;
                    self.append_class_atom(&mut frames, atom, token.span)?;
                    self.index += 1;
                }
                TokenKind::PosixClass { negated, name } => {
                    let atom = self.push_node(
                        AstNodeKind::PosixClass { negated, name },
                        token.span,
                        ExpansionEstimate::UNIT,
                    )?;
                    self.append_class_atom(&mut frames, atom, token.span)?;
                    self.index += 1;
                }
                TokenKind::End => {
                    let span = frames.last().map_or(open.span, |frame| frame.opener);
                    return Err(self.error(ParseErrorKind::UnclosedClass, span));
                }
                _ => return Err(self.error(ParseErrorKind::UnexpectedToken, token.span)),
            }
        }
    }

    fn handle_class_range(
        &mut self,
        frames: &mut [ClassParseFrame],
        span: SourceSpan,
    ) -> Result<(), ParseError> {
        let next_starts_atom = self
            .tokens
            .get(self.index + 1)
            .is_some_and(|token| is_class_atom_token(token.kind));
        let Some(frame) = frames.last_mut() else {
            return Err(self.error(ParseErrorKind::InvalidClassRange, span));
        };
        if next_starts_atom {
            if let Some(left) = frame.union.pop() {
                if self.is_class_range_endpoint(left) {
                    frame.pending_range = Some(PendingRange {
                        left,
                        operator_span: span,
                    });
                    frame.at_start = false;
                    return Ok(());
                }
                let left_span = self.nodes.get(left.index()).map_or(span, |node| node.span);
                frame.union.push(left);
                return Err(self.error(ParseErrorKind::InvalidClassRange, left_span));
            }
        }
        let literal = self.push_node(
            AstNodeKind::ClassLiteral('-'),
            span,
            ExpansionEstimate::UNIT,
        )?;
        frame.union.push(literal);
        frame.at_start = false;
        Ok(())
    }

    fn append_class_atom(
        &mut self,
        frames: &mut [ClassParseFrame],
        atom: NodeId,
        atom_span: SourceSpan,
    ) -> Result<(), ParseError> {
        let Some(frame) = frames.last_mut() else {
            return Err(self.error(ParseErrorKind::UnexpectedToken, atom_span));
        };
        if let Some(pending) = frame.pending_range.take() {
            if !self.is_class_range_endpoint(atom) {
                return Err(self.error(ParseErrorKind::InvalidClassRange, atom_span));
            }
            let start_span = self
                .nodes
                .get(pending.left.index())
                .map_or(pending.operator_span, |node| node.span);
            let Some(start) = self.class_range_value(pending.left) else {
                return Err(self.error(
                    ParseErrorKind::InvalidClassRange,
                    start_span.cover(atom_span),
                ));
            };
            let Some(end) = self.class_range_value(atom) else {
                return Err(self.error(
                    ParseErrorKind::InvalidClassRange,
                    start_span.cover(atom_span),
                ));
            };
            if start > end {
                return Err(self.error(
                    ParseErrorKind::InvalidClassRange,
                    start_span.cover(atom_span),
                ));
            }
            let range = self.push_node(
                AstNodeKind::ClassRange {
                    start: pending.left,
                    end: atom,
                },
                start_span.cover(atom_span),
                ExpansionEstimate::UNIT,
            )?;
            frame.union.push(range);
        } else {
            frame.union.push(atom);
        }
        frame.at_start = false;
        Ok(())
    }

    fn is_class_range_endpoint(&self, id: NodeId) -> bool {
        self.class_range_value(id).is_some()
    }

    fn class_range_value(&self, id: NodeId) -> Option<char> {
        match self.nodes.get(id.index())?.kind {
            AstNodeKind::ClassLiteral(value)
            | AstNodeKind::ClassEscape(
                Escape::Literal(value)
                | Escape::Control(value)
                | Escape::Hex(value)
                | Escape::Unicode(value),
            ) => Some(value),
            _ => None,
        }
    }

    fn begin_class_operator(
        &mut self,
        frames: &mut [ClassParseFrame],
        operator: ClassSetOperator,
        span: SourceSpan,
    ) -> Result<(), ParseError> {
        let Some(frame) = frames.last_mut() else {
            return Err(self.error(ParseErrorKind::InvalidClassOperator, span));
        };
        if frame.pending_range.is_some() {
            return Err(self.error(ParseErrorKind::InvalidClassOperator, span));
        }
        let union = core::mem::take(&mut frame.union);
        let right = if union.is_empty() {
            self.push_empty_class_union(SourceSpan::empty_at(span.byte_start, span.scalar_start))?
        } else {
            self.finish_class_union(union)?
        };
        let left = if let Some(existing) = frame.left.take() {
            let Some((pending, _)) = frame.pending_operator.take() else {
                return Err(self.error(ParseErrorKind::InvalidClassOperator, span));
            };
            self.push_class_set(existing, pending, right)?
        } else {
            right
        };
        frame.left = Some(left);
        frame.pending_operator = Some((operator, span));
        frame.at_start = false;
        Ok(())
    }

    fn finish_class_expression(
        &mut self,
        mut frame: ClassParseFrame,
        close: SourceSpan,
    ) -> Result<NodeId, ParseError> {
        if frame.pending_range.is_some() {
            return Err(self.error(ParseErrorKind::InvalidClassRange, close));
        }
        let right = if frame.union.is_empty() {
            if frame.left.is_none() {
                let span = frame
                    .pending_operator
                    .map_or(close, |(_, operator_span)| operator_span);
                return Err(self.error(ParseErrorKind::InvalidClassOperator, span));
            }
            self.push_empty_class_union(SourceSpan::empty_at(close.byte_start, close.scalar_start))?
        } else {
            self.finish_class_union(frame.union)?
        };
        if let Some(left) = frame.left.take() {
            let Some((operator, _)) = frame.pending_operator.take() else {
                return Err(self.error(ParseErrorKind::InvalidClassOperator, close));
            };
            self.push_class_set(left, operator, right)
        } else {
            Ok(right)
        }
    }

    fn finish_class_union(&mut self, children: Vec<NodeId>) -> Result<NodeId, ParseError> {
        match children.as_slice() {
            [] => Err(self.error(
                ParseErrorKind::InvalidClassOperator,
                SourceSpan::empty_at(0, 0),
            )),
            [only] => Ok(*only),
            _ => {
                let span = self.sequence_span(&children)?;
                self.push_node(
                    AstNodeKind::ClassUnion(children),
                    span,
                    ExpansionEstimate::UNIT,
                )
            }
        }
    }

    fn push_empty_class_union(&mut self, span: SourceSpan) -> Result<NodeId, ParseError> {
        self.push_node(
            AstNodeKind::ClassUnion(Vec::new()),
            span,
            ExpansionEstimate::UNIT,
        )
    }

    fn push_class_set(
        &mut self,
        left: NodeId,
        operator: ClassSetOperator,
        right: NodeId,
    ) -> Result<NodeId, ParseError> {
        let left_span = self
            .nodes
            .get(left.index())
            .map_or(SourceSpan::empty_at(0, 0), |node| node.span);
        let right_span = self
            .nodes
            .get(right.index())
            .map_or(left_span, |node| node.span);
        self.push_node(
            AstNodeKind::ClassSet {
                operator,
                left,
                right,
            },
            left_span.cover(right_span),
            ExpansionEstimate::UNIT,
        )
    }
}

fn is_class_atom_token(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Literal(_)
            | TokenKind::Escaped(_)
            | TokenKind::PosixClass { .. }
            | TokenKind::ClassOpen
    )
}

pub fn parse(
    pattern: &str,
    lexer_limits: LexerLimits,
    parser_limits: ParserLimits,
) -> Result<Ast, SyntaxError> {
    let tokens = lex(pattern, lexer_limits)?;
    Parser::new(pattern, tokens, parser_limits)
        .run()
        .map_err(SyntaxError::from)
}

#[cfg(test)]
#[path = "regex_syntax_inline_tests.rs"]
mod tests;
