//! Strictly safe, resource-bounded lexer for the candidate observability regex engine.
//!
//! This is an internal staging surface for `ASUP-REGEX-SYNTAX-V1`. It does not
//! compile or match patterns, and it is not wired into the incumbent
//! observability filter. The follow-on parser consumes these tokens.

use core::fmt;
use std::ops::Range;

pub const GRAMMAR_ID: &str = "ASUP-REGEX-SYNTAX-V1";
pub const DEFAULT_MAX_PATTERN_BYTES: usize = 1_048_576;
pub const DEFAULT_MAX_TOKENS: usize = 1_048_576;
pub const DEFAULT_MAX_AST_NODES: usize = 1_048_576;
pub const DEFAULT_MAX_NESTING: usize = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        }
    }

    fn run(mut self) -> Result<Vec<Token>, LexError> {
        while self.cursor.peek().is_some() {
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
                self.emit(TokenKind::GroupClose, start)
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
        if !self.cursor.consume("?") {
            return self.emit(TokenKind::GroupOpen, start);
        }

        if self.cursor.consume("=") || self.cursor.consume("!") {
            return Err(self.error(LexErrorKind::UnsupportedLookaround, start));
        }
        if self.cursor.starts_with("<=") || self.cursor.starts_with("<!") {
            self.cursor.bump();
            self.cursor.bump();
            return Err(self.error(LexErrorKind::UnsupportedLookaround, start));
        }
        if self.cursor.consume(":") {
            return self.emit(TokenKind::NonCapturingGroupOpen, start);
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
        self.emit(TokenKind::NamedCaptureGroupOpen { style, name }, start)
    }

    fn lex_flags(&mut self, start: Mark) -> Result<(), LexError> {
        let mut set = FlagSet::default();
        let mut clear = FlagSet::default();
        let mut clearing = false;
        let mut saw_set = false;
        let mut saw_clear = false;

        loop {
            let current = self.cursor.mark();
            let Some(value) = self.cursor.peek() else {
                return Err(self.error(LexErrorKind::InvalidFlag, start));
            };
            if value == ':' || value == ')' {
                if !saw_set && !saw_clear {
                    return Err(self.error(LexErrorKind::InvalidFlag, start));
                }
                self.cursor.bump();
                return self.emit(
                    TokenKind::FlagDirective {
                        set,
                        clear,
                        scoped: value == ':',
                    },
                    start,
                );
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
        let min = self.lex_decimal(start)?;
        if self.cursor.consume("}") {
            return self.emit(TokenKind::Counted(RepetitionRange::Exact(min)), start);
        }
        if !self.cursor.consume(",") {
            return Err(self.error(LexErrorKind::InvalidRepetition, start));
        }
        if self.cursor.consume("}") {
            return self.emit(TokenKind::Counted(RepetitionRange::AtLeast(min)), start);
        }
        let max = self.lex_decimal(start)?;
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
        while let Some(current) = self.cursor.peek() {
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
            'x' => Escape::Hex(self.lex_fixed_hex(start, 2)?),
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
        if !self.cursor.consume("{") {
            return Err(self.error(LexErrorKind::MalformedEscape, start));
        }
        let mut value = 0_u32;
        let mut digits = 0_usize;
        while let Some(current) = self.cursor.peek() {
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
        if digits == 0 || !self.cursor.consume("}") {
            return Err(self.error(LexErrorKind::MalformedEscape, start));
        }
        char::from_u32(value).ok_or_else(|| self.error(LexErrorKind::InvalidUnicodeScalar, start))
    }

    fn lex_unicode_class(&mut self, start: Mark, negated: bool) -> Result<Escape, LexError> {
        let name_start;
        let name;
        if self.cursor.consume("{") {
            name_start = self.cursor.mark();
            while self.cursor.peek().is_some_and(is_property_name_char) {
                self.cursor.bump();
            }
            name = self.cursor.span_from(name_start);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

struct Parser {
    tokens: Vec<Token>,
    index: usize,
    limits: ParserLimits,
    nodes: Vec<AstNode>,
    nesting: usize,
    max_nesting: usize,
    repetition_operators: usize,
    next_capture: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>, limits: ParserLimits) -> Self {
        let initial_capacity = tokens.len().min(limits.max_ast_nodes).min(4_096);
        Self {
            tokens,
            index: 0,
            limits,
            nodes: Vec::with_capacity(initial_capacity),
            nesting: 0,
            max_nesting: 0,
            repetition_operators: 0,
            next_capture: 1,
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
    Parser::new(tokens, parser_limits)
        .run()
        .map_err(SyntaxError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use regex::Regex as IncumbentRegex;

    fn default_lex(pattern: &str) -> Result<Vec<Token>, LexError> {
        lex(pattern, LexerLimits::default())
    }

    fn kinds(pattern: &str) -> Vec<TokenKind> {
        default_lex(pattern)
            .expect("fixture must lex")
            .into_iter()
            .map(|token| token.kind)
            .collect()
    }

    fn default_parse(pattern: &str) -> Result<Ast, SyntaxError> {
        parse(pattern, LexerLimits::default(), ParserLimits::default())
    }

    fn parse_error_kind(error: &SyntaxError) -> ParseErrorKind {
        match error {
            SyntaxError::Parse(error) => error.kind,
            SyntaxError::Lex(error) => panic!("expected parser error, got {error}"),
        }
    }

    fn diagnostic(error: &SyntaxError) -> (&'static str, SourceSpan) {
        match error {
            SyntaxError::Lex(error) => (error.kind.diagnostic_category(), error.span),
            SyntaxError::Parse(error) => (error.kind.diagnostic_category(), error.span),
        }
    }

    #[test]
    fn empty_pattern_is_an_explicit_zero_width_end_token() {
        let tokens = default_lex("").expect("empty pattern must lex");
        assert_eq!(
            tokens,
            vec![Token {
                kind: TokenKind::End,
                span: SourceSpan::empty_at(0, 0),
            }]
        );
    }

    #[test]
    fn lexes_top_level_operators_groups_flags_and_repetitions() {
        let pattern = "a|.(?:b)(?P<kind>c)(?<other>d)(?im-s:e)?*+{2}{3,}{4,5}^$";
        let tokens = default_lex(pattern).expect("operator fixture must lex");
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::Alternation)
        );
        assert!(tokens.iter().any(|token| token.kind == TokenKind::Dot));
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::NonCapturingGroupOpen)
        );
        assert!(tokens.iter().any(|token| matches!(
            token.kind,
            TokenKind::NamedCaptureGroupOpen {
                style: NamedCaptureStyle::Python,
                ..
            }
        )));
        assert!(tokens.iter().any(|token| matches!(
            token.kind,
            TokenKind::NamedCaptureGroupOpen {
                style: NamedCaptureStyle::Angle,
                ..
            }
        )));
        let flag = tokens
            .iter()
            .find_map(|token| match token.kind {
                TokenKind::FlagDirective { set, clear, scoped } => Some((set, clear, scoped)),
                _ => None,
            })
            .expect("flag token");
        assert!(flag.0.contains(Flag::CaseInsensitive));
        assert!(flag.0.contains(Flag::MultiLine));
        assert!(flag.1.contains(Flag::DotMatchesNewLine));
        assert!(flag.2);
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Counted(RepetitionRange::Exact(2)) })
        );
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Counted(RepetitionRange::AtLeast(3)) })
        );
        assert!(tokens.iter().any(|token| {
            token.kind == TokenKind::Counted(RepetitionRange::Bounded { min: 4, max: 5 })
        }));
    }

    #[test]
    fn named_capture_name_spans_are_borrowed_from_source() {
        let pattern = "(?P<κλειδί>x)";
        let tokens = default_lex(pattern).expect("Unicode capture name must lex");
        let name = tokens.iter().find_map(|token| match token.kind {
            TokenKind::NamedCaptureGroupOpen { name, .. } => name.source(pattern),
            _ => None,
        });
        assert_eq!(name, Some("κλειδί"));
    }

    #[test]
    fn byte_and_scalar_spans_round_trip_unicode_source() {
        let pattern = "é💩|x";
        let tokens = default_lex(pattern).expect("Unicode literal fixture must lex");
        assert_eq!(
            tokens[0].span,
            SourceSpan {
                byte_start: 0,
                byte_end: 2,
                scalar_start: 0,
                scalar_end: 1,
            }
        );
        assert_eq!(
            tokens[1].span,
            SourceSpan {
                byte_start: 2,
                byte_end: 6,
                scalar_start: 1,
                scalar_end: 2,
            }
        );
        assert_eq!(tokens[2].source(pattern), Some("|"));
        assert_eq!(tokens[3].source(pattern), Some("x"));
        assert_eq!(tokens[4].source(pattern), Some(""));
    }

    #[test]
    fn class_context_handles_leading_close_nested_classes_and_set_operators() {
        let pattern = "[]a&&[b]--c~~d-^]";
        let tokens = default_lex(pattern).expect("class fixture must lex");
        assert_eq!(tokens[0].kind, TokenKind::ClassOpen);
        assert_eq!(tokens[1].kind, TokenKind::Literal(']'));
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::ClassIntersection)
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::ClassDifference)
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::ClassSymmetricDifference)
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::ClassRange)
        );
        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.kind == TokenKind::ClassClose)
                .count(),
            2
        );
    }

    #[test]
    fn class_negation_posix_and_class_backspace_are_distinct() {
        let pattern = "[^[:^alpha:]\\b]";
        let tokens = default_lex(pattern).expect("POSIX fixture must lex");
        assert_eq!(tokens[1].kind, TokenKind::ClassNegation);
        let posix = tokens.iter().find_map(|token| match token.kind {
            TokenKind::PosixClass { negated, name } => Some((negated, name.source(pattern))),
            _ => None,
        });
        assert_eq!(posix, Some((true, Some("alpha"))));
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Escaped(Escape::Control('\u{8}')) })
        );
    }

    #[test]
    fn lexes_every_declared_escape_family() {
        let pattern = "\\*\\a\\f\\t\\n\\r\\v\\x73\\u{1F4A9}\\d\\D\\s\\S\\w\\W\\p{Greek}\\PL\\A\\z\\b\\B\\b{start}\\b{end}\\b{start-half}\\b{end-half}\\<\\>";
        let tokens = default_lex(pattern).expect("escape fixture must lex");
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Escaped(Escape::Literal('*')) })
        );
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Escaped(Escape::Hex('s')) })
        );
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Escaped(Escape::Unicode('💩')) })
        );
        assert!(tokens.iter().any(|token| {
            matches!(
                token.kind,
                TokenKind::Escaped(Escape::UnicodeClass { negated: false, .. })
            )
        }));
        assert!(tokens.iter().any(|token| {
            matches!(
                token.kind,
                TokenKind::Escaped(Escape::UnicodeClass { negated: true, .. })
            )
        }));
        for assertion in [
            Assertion::TextStart,
            Assertion::TextEnd,
            Assertion::WordBoundary,
            Assertion::NotWordBoundary,
            Assertion::WordStart,
            Assertion::WordEnd,
            Assertion::WordStartHalf,
            Assertion::WordEndHalf,
            Assertion::AsciiWordStart,
            Assertion::AsciiWordEnd,
        ] {
            assert!(
                tokens.iter().any(|token| {
                    token.kind == TokenKind::Escaped(Escape::Assertion(assertion))
                })
            );
        }
    }

    #[test]
    fn grammar_goldens_that_belong_to_lexer_all_tokenize() {
        for pattern in [
            "sam|samwise",
            "samwise|sam",
            "ab+?c",
            "(?P<kind>secret)-\\d+",
            "(?:ab){2,3}",
            "(?im-s:^x.$)",
            "[a-z&&[^aeiou]]+",
            "\\p{Greek}+",
            "\\x73\\u{65}cret",
            "(?-u:\\b)secret(?-u:\\b)",
            "",
            "(a+)+$",
        ] {
            let tokens = default_lex(pattern).unwrap_or_else(|error| {
                panic!("golden pattern failed with {error}");
            });
            assert_eq!(tokens.last().map(|token| token.kind), Some(TokenKind::End));
        }
    }

    #[test]
    fn stable_errors_cover_malformed_and_unsupported_inputs_without_source_text() {
        let cases = [
            ("\\", LexErrorKind::TrailingEscape),
            ("\\x0", LexErrorKind::MalformedEscape),
            ("\\xGG", LexErrorKind::MalformedEscape),
            ("\\u{}", LexErrorKind::MalformedEscape),
            ("\\u{D800}", LexErrorKind::InvalidUnicodeScalar),
            ("\\u{110000}", LexErrorKind::InvalidUnicodeScalar),
            ("\\q", LexErrorKind::MalformedEscape),
            ("\\1", LexErrorKind::UnsupportedBackreference),
            ("\\k<name>", LexErrorKind::UnsupportedBackreference),
            ("(?=x)", LexErrorKind::UnsupportedLookaround),
            ("(?<=x)", LexErrorKind::UnsupportedLookaround),
            ("(?q)", LexErrorKind::InvalidFlag),
            ("(?-)", LexErrorKind::InvalidFlag),
            ("a{3,2}", LexErrorKind::InvalidRepetition),
            ("a{4294967296}", LexErrorKind::InvalidRepetition),
        ];
        for (pattern, expected) in cases {
            let error = default_lex(pattern).expect_err("fixture must fail");
            assert_eq!(error.kind, expected);
            assert!(!error.to_string().contains(pattern));
            assert!(error.to_string().starts_with('['));
        }
    }

    #[test]
    fn repetition_u32_max_and_token_limit_boundaries_are_exact() {
        assert!(default_lex("a{4294967295}").is_ok());
        let limits = LexerLimits {
            max_pattern_bytes: 4,
            max_tokens: 4,
        };
        assert_eq!(
            lex("abc", limits).expect("three literals plus EOF").len(),
            4
        );
        let error = lex("abcd", limits).expect_err("EOF would exceed token budget");
        assert_eq!(error.kind, LexErrorKind::TokenLimit);
        assert_eq!(error.span, SourceSpan::empty_at(4, 4));
    }

    #[test]
    fn pattern_limit_rejects_before_tokenization_at_default_and_custom_bounds() {
        let limits = LexerLimits {
            max_pattern_bytes: 3,
            max_tokens: usize::MAX,
        };
        let error = lex("éé", limits).expect_err("four UTF-8 bytes exceed limit");
        assert_eq!(error.kind, LexErrorKind::PatternTooLarge);
        assert_eq!(error.span.byte_end, 4);
        assert_eq!(error.span.scalar_end, 2);

        let oversized = "a".repeat(DEFAULT_MAX_PATTERN_BYTES + 1);
        let error = default_lex(&oversized).expect_err("default pattern limit must apply");
        assert_eq!(error.kind, LexErrorKind::PatternTooLarge);
    }

    #[test]
    fn token_limit_also_bounds_adversarial_class_nesting() {
        let pattern = "[".repeat(128);
        let error = lex(
            &pattern,
            LexerLimits {
                max_pattern_bytes: pattern.len(),
                max_tokens: 16,
            },
        )
        .expect_err("class nesting cannot bypass token budget");
        assert_eq!(error.kind, LexErrorKind::TokenLimit);
        assert_eq!(error.span.byte_start, 16);
        assert_eq!(error.span.byte_end, 17);
    }

    #[test]
    fn minimized_fuzz_regressions_are_retained_and_replay_deterministically() {
        // Seed: 0x5A2C_0312. Replay:
        // cargo test --features metrics regex_syntax::tests::minimized_fuzz_regressions
        let corpus = [
            "",
            "\\",
            "\\u{",
            "\\u{D800}",
            "\\xF",
            "(?<",
            "(?--)",
            "[",
            "[]",
            "[^]",
            "[[:x:]]",
            "a{0,4294967295}",
            "a{4294967296}",
            "(?<!x)",
            "(x)\\9",
            "💩{2,3}",
        ];
        for pattern in corpus {
            let first = default_lex(pattern);
            let second = default_lex(pattern);
            assert_eq!(first, second, "nondeterministic replay");
        }
    }

    #[test]
    fn parser_accepts_every_frozen_positive_golden_with_reconciled_spans() {
        for pattern in [
            "sam|samwise",
            "samwise|sam",
            "ab+?c",
            "(?P<kind>secret)-\\d+",
            "(?:ab){2,3}",
            "(?im-s:^x.$)",
            "[a-z&&[^aeiou]]+",
            "\\p{Greek}+",
            "\\x73\\u{65}cret",
            "(?-u:\\b)secret(?-u:\\b)",
            "",
            "(a+)+$",
        ] {
            let ast = default_parse(pattern).unwrap_or_else(|error| {
                panic!("golden parser fixture failed with {error}");
            });
            assert!(ast.invariants_hold(pattern), "invalid AST for {pattern:?}");
            assert_eq!(ast.resources.ast_nodes, ast.nodes.len());
            assert_eq!(
                ast.node(ast.root).map(|node| node.span),
                Some(SourceSpan {
                    byte_start: 0,
                    byte_end: pattern.len(),
                    scalar_start: 0,
                    scalar_end: pattern.chars().count(),
                })
            );
        }
    }

    #[test]
    fn parser_flattens_ordered_precedence_without_reordering() {
        let ast = default_parse("a|bc|d").expect("precedence fixture must parse");
        let AstNodeKind::Alternation(branches) = &ast.node(ast.root).expect("root").kind else {
            panic!("root must be an alternation");
        };
        assert_eq!(branches.len(), 3);
        assert_eq!(
            ast.node(branches[0]).map(|node| &node.kind),
            Some(&AstNodeKind::Literal('a'))
        );
        let AstNodeKind::Concat(middle) = &ast.node(branches[1]).expect("middle branch").kind
        else {
            panic!("middle branch must be a concatenation");
        };
        assert_eq!(middle.len(), 2);
        assert_eq!(
            middle
                .iter()
                .filter_map(|id| ast.node(*id))
                .map(|node| &node.kind)
                .collect::<Vec<_>>(),
            vec![&AstNodeKind::Literal('b'), &AstNodeKind::Literal('c')]
        );
        assert_eq!(
            ast.node(branches[2]).map(|node| &node.kind),
            Some(&AstNodeKind::Literal('d'))
        );
    }

    #[test]
    fn parser_types_captures_flags_assertions_and_greediness() {
        let ast = default_parse("(?P<kind>a)(?:b)(?i-s:^c$)(?U)d+?")
            .expect("group and flag fixture must parse");
        assert!(ast.nodes.iter().any(|node| matches!(
            node.kind,
            AstNodeKind::Capture {
                index: 1,
                name: Some(_),
                style: Some(NamedCaptureStyle::Python),
                ..
            }
        )));
        assert!(
            ast.nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::NonCapturing { .. }))
        );
        assert!(ast.nodes.iter().any(|node| matches!(
            node.kind,
            AstNodeKind::Flags {
                scoped: true,
                child: Some(_),
                ..
            }
        )));
        assert!(ast.nodes.iter().any(|node| matches!(
            node.kind,
            AstNodeKind::Flags {
                scoped: false,
                child: None,
                ..
            }
        )));
        let repetition = ast
            .nodes
            .iter()
            .find(|node| matches!(node.kind, AstNodeKind::Repetition { .. }))
            .expect("repetition");
        assert!(matches!(
            repetition.kind,
            AstNodeKind::Repetition {
                quantifier: Quantifier::OneOrMore,
                // U swaps the default, then the explicit suffix swaps it back.
                greediness: Greediness::Greedy,
                ..
            }
        ));
    }

    #[test]
    fn class_parser_preserves_range_union_negation_and_left_set_precedence() {
        let ast = default_parse("[a-z&&[^aeiou]--[x~~y]]").expect("class fixture must parse");
        let outer = ast
            .nodes
            .iter()
            .find(|node| {
                matches!(node.kind, AstNodeKind::Class { negated: false, .. })
                    && node.span.byte_start == 0
            })
            .expect("outer class");
        let AstNodeKind::Class { expression, .. } = outer.kind else {
            panic!("outer class kind");
        };
        let AstNodeKind::ClassSet {
            operator: ClassSetOperator::Difference,
            left,
            right,
        } = ast.node(expression).expect("class expression").kind
        else {
            panic!("outer set expression must be left-associated difference");
        };
        assert!(matches!(
            ast.node(left).map(|node| &node.kind),
            Some(AstNodeKind::ClassSet {
                operator: ClassSetOperator::Intersection,
                ..
            })
        ));
        assert!(matches!(
            ast.node(right).map(|node| &node.kind),
            Some(AstNodeKind::Class { negated: false, .. })
        ));
        assert!(
            ast.nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::ClassRange { .. }))
        );
        assert!(
            ast.nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::Class { negated: true, .. }))
        );
    }

    #[test]
    fn parser_reports_typed_structural_errors_with_stable_private_display() {
        let cases = [
            ("(", ParseErrorKind::UnclosedGroup),
            ("[", ParseErrorKind::UnclosedClass),
            (")", ParseErrorKind::UnexpectedGroupClose),
            ("*a", ParseErrorKind::InvalidRepetition),
            ("(?i)*", ParseErrorKind::InvalidRepetition),
            ("[\\A]", ParseErrorKind::InvalidClassEscape),
            ("[\\b]", ParseErrorKind::InvalidClassEscape),
            ("[a-\\d]", ParseErrorKind::InvalidClassRange),
            ("[\\w-a]", ParseErrorKind::InvalidClassRange),
            ("[z-a]", ParseErrorKind::InvalidClassRange),
        ];
        for (pattern, expected) in cases {
            let error = default_parse(pattern).expect_err("fixture must fail");
            assert_eq!(parse_error_kind(&error), expected, "pattern {pattern:?}");
            assert!(error.to_string().starts_with("[RGX-PARSE-E"));
        }

        let private_pattern = "(private-source-canary";
        let rendered = default_parse(private_pattern)
            .expect_err("unclosed private pattern must fail")
            .to_string();
        assert!(!rendered.contains("private-source-canary"));

        let error = default_parse("\\").expect_err("lexer failure must be retained");
        assert!(matches!(
            error,
            SyntaxError::Lex(LexError {
                kind: LexErrorKind::TrailingEscape,
                ..
            })
        ));
    }

    #[test]
    fn frozen_invalid_goldens_match_diagnostic_category_and_span() {
        let cases = [
            ("(?=secret)", "RGX-DIAG-UNSUPPORTED-LOOKAROUND", (0, 3)),
            ("(secret)\\1", "RGX-DIAG-UNSUPPORTED-BACKREFERENCE", (8, 10)),
            ("(", "RGX-DIAG-UNCLOSED-GROUP", (0, 1)),
            ("[", "RGX-DIAG-UNCLOSED-CLASS", (0, 1)),
            ("a{3,2}", "RGX-DIAG-INVALID-REPETITION", (1, 6)),
            ("(?q)secret", "RGX-DIAG-INVALID-FLAG", (2, 3)),
            ("(?-u:.)", "RGX-DIAG-INVALID-UTF8", (0, 7)),
            ("\\", "RGX-DIAG-TRAILING-ESCAPE", (0, 1)),
        ];
        for (pattern, expected_category, (byte_start, byte_end)) in cases {
            let error = default_parse(pattern).expect_err("invalid golden must fail");
            let (category, span) = diagnostic(&error);
            assert_eq!(category, expected_category, "pattern {pattern:?}");
            assert_eq!(
                (span.byte_start, span.byte_end),
                (byte_start, byte_end),
                "pattern {pattern:?}"
            );
        }
    }

    #[test]
    fn directly_nested_repetition_matches_incumbent_syntax_and_stays_bounded() {
        for pattern in ["a**", "a++", "a{1}+", "a+{2}"] {
            assert!(
                IncumbentRegex::new(pattern).is_ok(),
                "incumbent drifted for {pattern:?}"
            );
            let ast = default_parse(pattern).expect("direct nested repetition must parse");
            assert!(ast.invariants_hold(pattern));
            assert_eq!(ast.resources.repetition_operators, 2);
            assert_eq!(
                ast.nodes
                    .iter()
                    .filter(|node| matches!(node.kind, AstNodeKind::Repetition { .. }))
                    .count(),
                2
            );
        }

        let SyntaxError::Parse(error) =
            default_parse("(?i)*").expect_err("a flag directive is not repeatable")
        else {
            panic!("expected parser error");
        };
        assert_eq!(error.kind, ParseErrorKind::InvalidRepetition);
        assert_eq!(
            error.span,
            SourceSpan {
                byte_start: 4,
                byte_end: 4,
                scalar_start: 4,
                scalar_end: 4,
            }
        );
    }

    #[test]
    fn class_set_operators_preserve_incumbent_empty_operands() {
        for pattern in ["[a&&]", "[&&a]", "[a--]", "[--a]", "[a~~]", "[~~a]"] {
            assert!(
                IncumbentRegex::new(pattern).is_ok(),
                "incumbent drifted for {pattern:?}"
            );
            let ast = default_parse(pattern).expect("empty set operand must parse");
            assert!(ast.invariants_hold(pattern));
            assert!(ast.nodes.iter().any(|node| matches!(
                &node.kind,
                AstNodeKind::ClassUnion(children) if children.is_empty()
            )));
            assert!(
                ast.nodes
                    .iter()
                    .any(|node| matches!(node.kind, AstNodeKind::ClassSet { .. }))
            );
        }
    }

    #[test]
    fn quarantined_incumbent_and_candidate_compile_states_match_adversarial_corpus() {
        let corpus = [
            "token-[A-F0-9]{8}",
            "cat|dog",
            "(?P<kind>secret)-\\d+",
            "(?:ab){2,3}",
            "\\Asecret\\z",
            "(?m)^secret$",
            "(?s)BEGIN.*END",
            "(?mR)^secret$",
            "(?i)σ",
            "(?x) secret \\s+ \\d+",
            "(?U)a+",
            "\\p{Greek}+",
            "\\d+",
            "[[:digit:]]+",
            "[a-z&&[^aeiou]]+",
            "[0-9--4]+",
            "[a-g~~b-h]+",
            "\\bκόσμος\\b",
            "(?-u:\\b)secret(?-u:\\b)",
            "\\x73\\u{65}cret",
            "",
            "^",
            "[a&&b]",
            "(a+)+$",
            "(?=secret)",
            "(secret)\\1",
            "(",
            "[",
            "a{3,2}",
            "(?q)secret",
            "(?x:a # comment\n b)",
            "(?x)[ a-z ]",
            "(?x)a{ 2 , 3 }",
            "(?x)\\x { 53 }",
            "(?x)\\u { 53 }",
            "(?x)\\p { Greek }",
            "(?x)( ?P<foo> a )",
            "(?x)( ?: a )",
            "(?x:\\ )",
            "(?P<name>a)|(?P<name>b)",
            "^*",
            "\\b+",
            "(?i)*",
            "a**",
            "a{1}+",
            "[a-\\d]",
            "[\\w-a]",
            "[z-a]",
            "[\\A]",
            "[\\b]",
            "[a&&]",
            "[&&a]",
            "[a--]",
            "[--a]",
            "[a~~]",
            "[~~a]",
            "\\p{DefinitelyNotAProperty}",
            "[[:definitelynot:]]",
            "(?-u:\\pL)",
            "(?-u:\\xFF)",
            "(?>a)",
            "a++",
        ];
        let mismatches = corpus
            .iter()
            .filter_map(|pattern| {
                let incumbent = IncumbentRegex::new(pattern).is_ok();
                let candidate = default_parse(pattern).is_ok();
                (incumbent != candidate).then_some((*pattern, incumbent, candidate))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            mismatches,
            vec![
                ("(?x)a{ 2 , 3 }", true, false),
                ("(?x)\\x { 53 }", true, false),
                ("(?x)\\u { 53 }", true, false),
                ("(?x)\\p { Greek }", true, false),
                ("(?P<name>a)|(?P<name>b)", false, true),
                ("\\p{DefinitelyNotAProperty}", false, true),
                ("(?-u:\\pL)", false, true),
                ("(?-u:\\xFF)", false, true),
            ],
            "quarantined oracle divergence set drifted"
        );
    }

    // The incumbent patterns below are deliberately trivial. This test pins
    // incumbent `(?x)` whitespace/comment semantics against the candidate
    // parser, so `clippy::trivial_regex`'s suggestion to use plain string
    // operations would delete the exact behavior under test. Suppressed rather
    // than "simplified" (br-asupersync-vdbvkv chain; raised with the R3.1.4
    // owner in Agent Mail thread asupersync-5z2scg.8.3.1.4 before landing).
    #[allow(clippy::trivial_regex)]
    #[test]
    fn minimized_semantic_divergences_remain_explicit_cutover_blockers() {
        let incumbent = IncumbentRegex::new("(?x)a b").expect("incumbent x pattern");
        assert!(incumbent.is_match("ab"));
        assert!(!incumbent.is_match("a b"));
        let whitespace = default_parse("(?x)a b").expect("candidate accepts global x");
        assert!(
            whitespace
                .nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::Literal(' '))),
            "remove this blocker only with the terminal receipt update"
        );

        let incumbent = IncumbentRegex::new("(?x)a # comment\n b").expect("incumbent x comment");
        assert!(incumbent.is_match("ab"));
        let comment = default_parse("(?x)a # comment\n b").expect("candidate accepts x comment");
        assert!(
            comment
                .nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::Literal('#'))),
            "remove this blocker only with the terminal receipt update"
        );

        let incumbent = IncumbentRegex::new("(?x)[ a-z ]").expect("incumbent x class");
        assert!(incumbent.is_match("a"));
        assert!(!incumbent.is_match(" "));
        let class = default_parse("(?x)[ a-z ]").expect("candidate accepts x class");
        assert!(
            class
                .nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::ClassLiteral(' '))),
            "remove this blocker only with the terminal receipt update"
        );

        let incumbent = IncumbentRegex::new("(?x)( ?P<foo> a )").expect("incumbent spaced capture");
        assert_eq!(
            incumbent.capture_names().flatten().collect::<Vec<_>>(),
            ["foo"]
        );
        let capture = default_parse("(?x)( ?P<foo> a )").expect("candidate accepts spaced group");
        assert!(
            !capture
                .nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::Capture { name: Some(_), .. })),
            "remove this blocker only with the terminal receipt update"
        );
    }

    #[test]
    fn invalid_class_ranges_report_the_canonical_endpoint_span() {
        let cases = [
            (
                "[a-\\d]",
                SourceSpan {
                    byte_start: 3,
                    byte_end: 5,
                    scalar_start: 3,
                    scalar_end: 5,
                },
            ),
            (
                "[\\w-a]",
                SourceSpan {
                    byte_start: 1,
                    byte_end: 3,
                    scalar_start: 1,
                    scalar_end: 3,
                },
            ),
            (
                "[z-a]",
                SourceSpan {
                    byte_start: 1,
                    byte_end: 4,
                    scalar_start: 1,
                    scalar_end: 4,
                },
            ),
        ];
        for (pattern, expected_span) in cases {
            let SyntaxError::Parse(error) =
                default_parse(pattern).expect_err("invalid class range must fail")
            else {
                panic!("expected parser error");
            };
            assert_eq!(error.kind, ParseErrorKind::InvalidClassRange);
            assert_eq!(error.span, expected_span, "pattern {pattern:?}");
        }
    }

    #[test]
    fn unicode_disablement_rejects_unsafe_dot_at_the_scoped_group_span() {
        let error = default_parse("(?-u:.)").expect_err("byte-mode dot violates UTF-8");
        let SyntaxError::Parse(error) = error else {
            panic!("expected parser error");
        };
        assert_eq!(error.kind, ParseErrorKind::InvalidUtf8Invariant);
        assert_eq!(
            error.span,
            SourceSpan {
                byte_start: 0,
                byte_end: 7,
                scalar_start: 0,
                scalar_end: 7,
            }
        );
        assert!(default_parse("(?-u:\\b)").is_ok());
        assert_eq!(
            parse_error_kind(&default_parse("(?-u).").expect_err("global byte dot")),
            ParseErrorKind::InvalidUtf8Invariant
        );
    }

    #[test]
    fn parser_node_and_nesting_limits_are_exact_and_preallocation_safe() {
        let one = parse(
            "a",
            LexerLimits::default(),
            ParserLimits {
                max_ast_nodes: 1,
                max_nesting: DEFAULT_MAX_NESTING,
            },
        )
        .expect("one literal needs one node");
        assert_eq!(one.nodes.len(), 1);

        let error = parse(
            "ab",
            LexerLimits::default(),
            ParserLimits {
                max_ast_nodes: 2,
                max_nesting: DEFAULT_MAX_NESTING,
            },
        )
        .expect_err("concat node would exceed limit");
        assert_eq!(parse_error_kind(&error), ParseErrorKind::AstNodeLimit);

        let mut at_limit = "(".repeat(DEFAULT_MAX_NESTING);
        at_limit.push('a');
        at_limit.push_str(&")".repeat(DEFAULT_MAX_NESTING));
        let ast = default_parse(&at_limit).expect("exact nesting limit");
        assert_eq!(ast.resources.max_nesting, DEFAULT_MAX_NESTING);

        let mut above_limit = "(".repeat(DEFAULT_MAX_NESTING + 1);
        above_limit.push('a');
        above_limit.push_str(&")".repeat(DEFAULT_MAX_NESTING + 1));
        let error = default_parse(&above_limit).expect_err("nesting limit must fail");
        assert_eq!(parse_error_kind(&error), ParseErrorKind::NestingLimit);
    }

    #[test]
    fn repetition_accounting_is_bounded_without_ast_expansion() {
        let ast = default_parse("(a{2}){3}").expect("nested counted repetition");
        assert_eq!(ast.resources.repetition_operators, 2);
        assert_eq!(
            ast.resources.repetition_expansion,
            ExpansionEstimate {
                minimum: ExpansionBound::Finite(6),
                maximum: ExpansionBound::Finite(6),
            }
        );

        let unbounded = default_parse("a*").expect("unbounded repetition");
        assert_eq!(
            unbounded.resources.repetition_expansion.maximum,
            ExpansionBound::Unbounded
        );

        let maximum = u32::MAX;
        let pattern =
            format!("((((a{{{maximum}}}){{{maximum}}}){{{maximum}}}){{{maximum}}}){{{maximum}}}");
        let overflowed = default_parse(&pattern).expect("accounting overflow is represented");
        assert_eq!(
            overflowed.resources.repetition_expansion.maximum,
            ExpansionBound::Overflowed
        );
        assert!(
            overflowed.nodes.len() < 32,
            "repetitions must never allocate expanded copies"
        );
    }

    #[test]
    fn minimized_parser_regressions_are_retained_and_replay_deterministically() {
        // Seed: 0x5A2C_0313. Replay:
        // cargo test --features metrics regex_syntax::tests::minimized_parser_regressions
        let corpus = [
            "",
            "|",
            "a|",
            "|a",
            "()",
            "(a",
            "a)",
            "a??",
            "a???",
            "[a-z]",
            "[-a]",
            "[a-]",
            "[\\A]",
            "[\\b]",
            "[a-\\d]",
            "[\\w-a]",
            "[z-a]",
            "[a&&b]",
            "[a&&]",
            "[a-z&&[^aeiou]]",
            "(?-u:.)",
            "(?-u:\\b)",
            "(a{4294967295}){4294967295}",
        ];
        for pattern in corpus {
            let first = default_parse(pattern);
            let second = default_parse(pattern);
            assert_eq!(first, second, "nondeterministic parser replay");
            if let Ok(ast) = first {
                assert!(ast.invariants_hold(pattern));
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn literal_token_spans_round_trip_for_arbitrary_unicode(
            scalars in proptest::collection::vec(
                any::<char>().prop_filter("exclude regex metacharacters", |value| {
                    !matches!(value, '|' | '.' | '(' | ')' | '[' | '?' | '*' | '+' | '{' | '^' | '$' | '\\')
                }),
                0..128,
            ),
        ) {
            let pattern: String = scalars.iter().collect();
            let tokens = default_lex(&pattern).expect("literal-only pattern must lex");
            prop_assert_eq!(tokens.len(), scalars.len() + 1);
            for (token, expected) in tokens.iter().zip(scalars.iter()) {
                prop_assert_eq!(token.kind, TokenKind::Literal(*expected));
                let mut encoded = [0_u8; 4];
                let expected_source: &str = expected.encode_utf8(&mut encoded);
                prop_assert_eq!(token.source(&pattern), Some(expected_source));
            }
            prop_assert_eq!(tokens.last().map(|token| token.kind), Some(TokenKind::End));
        }

        #[test]
        fn arbitrary_utf8_is_panic_free_deterministic_and_span_safe(pattern in any::<String>()) {
            let first = default_lex(&pattern);
            let second = default_lex(&pattern);
            prop_assert_eq!(&first, &second);
            if let Ok(tokens) = first {
                for token in tokens {
                    prop_assert!(token.span.byte_start <= token.span.byte_end);
                    prop_assert!(token.span.scalar_start <= token.span.scalar_end);
                    prop_assert!(token.source(&pattern).is_some());
                }
            }
        }

        #[test]
        fn arbitrary_utf8_parser_is_deterministic_panic_free_and_reconciled(
            pattern in any::<String>(),
        ) {
            let first = default_parse(&pattern);
            let second = default_parse(&pattern);
            prop_assert_eq!(&first, &second);
            if let Ok(ast) = first {
                prop_assert!(ast.invariants_hold(&pattern));
                prop_assert!(ast.resources.max_nesting <= DEFAULT_MAX_NESTING);
                prop_assert!(ast.resources.ast_nodes <= DEFAULT_MAX_AST_NODES);
            }
        }

        #[test]
        fn alternation_and_concatenation_match_the_flat_precedence_model(
            segments in proptest::collection::vec("[a-z]{1,8}", 1..8),
        ) {
            let pattern = segments.join("|");
            let ast = default_parse(&pattern).expect("model pattern must parse");
            prop_assert!(ast.invariants_hold(&pattern));
            if segments.len() == 1 {
                prop_assert!(!matches!(
                    ast.node(ast.root).map(|node| &node.kind),
                    Some(AstNodeKind::Alternation(_))
                ));
            } else {
                let Some(AstNode {
                    kind: AstNodeKind::Alternation(branches),
                    ..
                }) = ast.node(ast.root)
                else {
                    return Err(TestCaseError::fail("root must be an alternation"));
                };
                prop_assert_eq!(branches.len(), segments.len());
            }
        }
    }

    #[test]
    fn grammar_identifier_and_default_limits_match_frozen_contract() {
        assert_eq!(GRAMMAR_ID, "ASUP-REGEX-SYNTAX-V1");
        assert_eq!(
            LexerLimits::default(),
            LexerLimits {
                max_pattern_bytes: 1_048_576,
                max_tokens: 1_048_576,
            }
        );
        assert_eq!(
            ParserLimits::default(),
            ParserLimits {
                max_ast_nodes: 1_048_576,
                max_nesting: 250,
            }
        );
    }

    #[test]
    fn every_token_span_round_trips_for_mixed_fixture() {
        let pattern = "(?i:a💩)[^x-z]\\p{Greek}{2,3}|$";
        for token in default_lex(pattern).expect("mixed fixture must lex") {
            assert!(token.source(pattern).is_some());
            assert!(pattern.is_char_boundary(token.span.byte_start));
            assert!(pattern.is_char_boundary(token.span.byte_end));
        }
    }

    #[test]
    fn top_level_token_kind_snapshot_is_stable() {
        assert_eq!(
            kinds("a|b.*?+$"),
            vec![
                TokenKind::Literal('a'),
                TokenKind::Alternation,
                TokenKind::Literal('b'),
                TokenKind::Dot,
                TokenKind::ZeroOrMore,
                TokenKind::ZeroOrOne,
                TokenKind::OneOrMore,
                TokenKind::LineEnd,
                TokenKind::End,
            ]
        );
    }
}
