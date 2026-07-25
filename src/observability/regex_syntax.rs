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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
