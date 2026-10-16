//! Console rendering primitives for terminal diagnostics and debugging.
//!
//! This module provides best-effort terminal capability detection and styled
//! text rendering without forcing any output. Consumers can use `Console` with
//! an explicit writer to keep output deterministic in tests.

use crate::tracing_compat::{debug, info, trace};
use parking_lot::Mutex;
use std::io::{self, IsTerminal, Write};

/// ANSI reset sequence.
const ANSI_RESET: &str = "\x1b[0m";
/// ANSI clear screen + home cursor.
const ANSI_CLEAR: &str = "\x1b[2J\x1b[H";
/// ANSI hide cursor.
const ANSI_CURSOR_HIDE: &str = "\x1b[?25l";
/// ANSI show cursor.
const ANSI_CURSOR_SHOW: &str = "\x1b[?25h";

/// Console for rendering styled output with terminal detection.
pub struct Console {
    caps: Capabilities,
    writer: Mutex<Box<dyn Write + Send>>,
    color_mode: ColorMode,
}

impl std::fmt::Debug for Console {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Console")
            .field("caps", &self.caps)
            .field("color_mode", &self.color_mode)
            .finish_non_exhaustive()
    }
}

impl Console {
    /// Create a console that writes to stdout with auto-detected capabilities.
    #[must_use]
    pub fn new() -> Self {
        let caps = Capabilities::detect_stdout();
        info!(
            is_tty = caps.is_tty,
            color_support = ?caps.color_support,
            "console created"
        );
        Self::with_caps(io::stdout(), caps, ColorMode::Auto)
    }

    /// Create a console that writes to the provided writer with capabilities
    /// derived from that writer's terminal status.
    #[must_use]
    pub fn with_writer<W: Write + Send + IsTerminal + 'static>(writer: W) -> Self {
        let caps = Capabilities::detect_terminal(writer.is_terminal());
        Self::with_caps(writer, caps, ColorMode::Auto)
    }

    /// Create a console with explicit capabilities and color mode.
    #[must_use]
    pub fn with_caps<W: Write + Send + 'static>(
        writer: W,
        caps: Capabilities,
        color_mode: ColorMode,
    ) -> Self {
        Self {
            caps,
            writer: Mutex::new(Box::new(writer)),
            color_mode,
        }
    }

    /// Returns the detected terminal capabilities.
    #[must_use]
    #[inline]
    pub fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    /// Returns the current color mode.
    #[must_use]
    #[inline]
    pub fn color_mode(&self) -> ColorMode {
        self.color_mode
    }

    /// Set the color mode for subsequent renders.
    pub fn set_color_mode(&mut self, mode: ColorMode) {
        self.color_mode = mode;
    }

    /// Render content without a trailing newline.
    pub fn print(&self, content: &dyn Render) -> io::Result<()> {
        self.write_render(content, false)
    }

    /// Render content with a trailing newline.
    pub fn println(&self, content: &dyn Render) -> io::Result<()> {
        self.write_render(content, true)
    }

    /// Clear the screen (no-op if ANSI output is disabled).
    pub fn clear(&self) -> io::Result<()> {
        self.write_ansi(ANSI_CLEAR)
    }

    /// Hide the cursor (no-op if ANSI output is disabled).
    pub fn cursor_hide(&self) -> io::Result<()> {
        self.write_ansi(ANSI_CURSOR_HIDE)
    }

    /// Show the cursor (no-op if ANSI output is disabled).
    pub fn cursor_show(&self) -> io::Result<()> {
        self.write_ansi(ANSI_CURSOR_SHOW)
    }

    fn write_render(&self, content: &dyn Render, newline: bool) -> io::Result<()> {
        let mut buf = String::new();
        content.render(&mut buf, &self.caps, self.color_mode);
        if newline {
            buf.push('\n');
        }
        trace!(bytes = buf.len(), "console render");
        self.write_raw(buf.as_bytes())
    }

    fn write_ansi(&self, seq: &str) -> io::Result<()> {
        if !self.emit_ansi() {
            return Ok(());
        }
        trace!(sequence = seq, "console ansi");
        self.write_raw(seq.as_bytes())
    }

    fn write_raw(&self, bytes: &[u8]) -> io::Result<()> {
        let mut guard = self.writer.lock();
        guard.write_all(bytes)?;
        guard.flush()
    }

    fn emit_ansi(&self) -> bool {
        match self.color_mode {
            ColorMode::Never => false,
            ColorMode::Auto => self.caps.is_tty,
            ColorMode::Always => true,
        }
    }

    #[cfg(test)]
    fn effective_color_support(&self) -> ColorSupport {
        match self.color_mode {
            ColorMode::Never => ColorSupport::None,
            ColorMode::Auto => self.caps.color_support,
            ColorMode::Always => {
                if self.caps.color_support == ColorSupport::None {
                    ColorSupport::Basic
                } else {
                    self.caps.color_support
                }
            }
        }
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

/// Terminal capability information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// True if the output target is a TTY.
    pub is_tty: bool,
    /// Detected color support.
    pub color_support: ColorSupport,
    /// Terminal width in columns.
    pub width: u16,
    /// Terminal height in rows.
    pub height: u16,
    /// True if UTF-8 output is likely supported.
    pub unicode: bool,
}

impl Capabilities {
    /// Detect capabilities for stdout using environment hints.
    #[must_use]
    pub fn detect_stdout() -> Self {
        Self::detect_terminal(io::stdout().is_terminal())
    }

    /// Detect capabilities using explicit inputs (useful for tests).
    #[must_use]
    fn detect_from(env: &dyn Env, is_tty: bool, size: Option<(u16, u16)>) -> Self {
        let color_support = ColorSupport::detect(env, is_tty);
        let unicode = detect_unicode(env);
        let (width, height) = size.unwrap_or((80, 24));
        debug!(
            is_tty,
            ?color_support,
            width,
            height,
            unicode,
            "detected console capabilities"
        );
        Self {
            is_tty,
            color_support,
            width,
            height,
            unicode,
        }
    }

    #[must_use]
    fn detect_terminal(is_tty: bool) -> Self {
        let env = OsEnv;
        let size = size_from_env(&env);
        Self::detect_from(&env, is_tty, size)
    }
}

/// Color mode selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// Enable color only when output is a TTY.
    Auto,
    /// Always emit ANSI codes.
    Always,
    /// Never emit ANSI codes.
    Never,
}

/// Supported color depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorSupport {
    /// No color support.
    None,
    /// 16-color ANSI.
    Basic,
    /// 256-color ANSI.
    Extended,
    /// 24-bit true color.
    TrueColor,
}

impl ColorSupport {
    fn detect(env: &dyn Env, is_tty: bool) -> Self {
        if !is_tty {
            return Self::None;
        }
        if env.var("NO_COLOR").is_some() {
            return Self::None;
        }
        if let Some(value) = env.var("FORCE_COLOR") {
            if is_truthy(&value) {
                return Self::TrueColor;
            }
        }
        if let Some(value) = env.var("COLORTERM") {
            let v = value.to_ascii_lowercase();
            if v.contains("truecolor") || v.contains("24bit") {
                return Self::TrueColor;
            }
        }
        if let Some(value) = env.var("TERM") {
            let v = value.to_ascii_lowercase();
            if v.contains("256color") {
                return Self::Extended;
            }
            if v.contains("color") || v.contains("ansi") || v.contains("xterm") {
                return Self::Basic;
            }
        }
        Self::Basic
    }
}

/// Color value for styled output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    /// Basic black.
    Black,
    /// Basic red.
    Red,
    /// Basic green.
    Green,
    /// Basic yellow.
    Yellow,
    /// Basic blue.
    Blue,
    /// Basic magenta.
    Magenta,
    /// Basic cyan.
    Cyan,
    /// Basic white.
    White,
    /// Bright black (gray).
    BrightBlack,
    /// Bright red.
    BrightRed,
    /// Bright green.
    BrightGreen,
    /// Bright yellow.
    BrightYellow,
    /// Bright blue.
    BrightBlue,
    /// Bright magenta.
    BrightMagenta,
    /// Bright cyan.
    BrightCyan,
    /// Bright white.
    BrightWhite,
    /// Indexed 256-color palette.
    Index(u8),
    /// 24-bit RGB color.
    Rgb(u8, u8, u8),
}

impl Color {
    /// Parse a hex color string into an RGB color.
    ///
    /// Accepts "RRGGBB" or "#RRGGBB".
    #[must_use]
    pub fn from_hex(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        let hex = trimmed.strip_prefix('#').unwrap_or(trimmed);
        if hex.len() != 6 || !hex.is_ascii() {
            return None;
        }
        let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
        let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
        let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
        Some(Self::Rgb(r, g, b))
    }

    fn ansi_fg(self, support: ColorSupport) -> Option<String> {
        ansi_color_code(self, support, true)
    }

    fn ansi_bg(self, support: ColorSupport) -> Option<String> {
        ansi_color_code(self, support, false)
    }
}

/// Text style configuration.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Style {
    /// Foreground color.
    pub fg: Option<Color>,
    /// Background color.
    pub bg: Option<Color>,
    /// Bold text.
    pub bold: bool,
    /// Italic text.
    pub italic: bool,
    /// Underlined text.
    pub underline: bool,
    /// Dim text.
    pub dim: bool,
}

impl Style {
    /// Create a new empty style.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set foreground color.
    #[must_use]
    pub fn fg(mut self, color: Color) -> Self {
        self.fg = Some(color);
        self
    }

    /// Set background color.
    #[must_use]
    pub fn bg(mut self, color: Color) -> Self {
        self.bg = Some(color);
        self
    }

    /// Enable bold.
    #[must_use]
    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    /// Enable dim.
    #[must_use]
    pub fn dim(mut self) -> Self {
        self.dim = true;
        self
    }

    /// Enable italic.
    #[must_use]
    pub fn italic(mut self) -> Self {
        self.italic = true;
        self
    }

    /// Enable underline.
    #[must_use]
    pub fn underline(mut self) -> Self {
        self.underline = true;
        self
    }

    fn is_plain(&self) -> bool {
        self.fg.is_none()
            && self.bg.is_none()
            && !self.bold
            && !self.italic
            && !self.underline
            && !self.dim
    }

    fn render_to(&self, out: &mut String, content: &str, support: ColorSupport, emit_ansi: bool) {
        if self.is_plain() || !emit_ansi || support == ColorSupport::None {
            out.push_str(content);
            return;
        }

        let mut codes: Vec<String> = Vec::new();
        if self.bold {
            codes.push("1".to_string());
        }
        if self.dim {
            codes.push("2".to_string());
        }
        if self.italic {
            codes.push("3".to_string());
        }
        if self.underline {
            codes.push("4".to_string());
        }
        if let Some(fg) = self.fg {
            if let Some(code) = fg.ansi_fg(support) {
                codes.push(code);
            }
        }
        if let Some(bg) = self.bg {
            if let Some(code) = bg.ansi_bg(support) {
                codes.push(code);
            }
        }

        if codes.is_empty() {
            out.push_str(content);
            return;
        }

        out.push_str("\x1b[");
        out.push_str(&codes.join(";"));
        out.push('m');
        out.push_str(content);
        out.push_str(ANSI_RESET);
    }
}

/// Styled text container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text {
    content: String,
    style: Style,
}

impl Text {
    /// Create a new text value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            content: value.into(),
            style: Style::new(),
        }
    }

    /// Apply foreground color.
    #[must_use]
    pub fn fg(mut self, color: Color) -> Self {
        self.style = self.style.fg(color);
        self
    }

    /// Apply background color.
    #[must_use]
    pub fn bg(mut self, color: Color) -> Self {
        self.style = self.style.bg(color);
        self
    }

    /// Apply bold.
    #[must_use]
    pub fn bold(mut self) -> Self {
        self.style = self.style.bold();
        self
    }

    /// Apply dim.
    #[must_use]
    pub fn dim(mut self) -> Self {
        self.style = self.style.dim();
        self
    }

    /// Apply italic.
    #[must_use]
    pub fn italic(mut self) -> Self {
        self.style = self.style.italic();
        self
    }

    /// Apply underline.
    #[must_use]
    pub fn underline(mut self) -> Self {
        self.style = self.style.underline();
        self
    }

    /// Access the raw content.
    #[must_use]
    #[inline]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Access the style.
    #[must_use]
    #[inline]
    pub fn style(&self) -> &Style {
        &self.style
    }
}

/// Renderable console content.
/// Sanitize ANSI escape sequences from user-provided content.
///
/// **Security**: This function prevents ANSI injection attacks by filtering out
/// escape sequences that could manipulate the terminal. Only printable
/// characters, tabs, and newlines are preserved.
#[must_use]
fn sanitize_ansi_escape_sequences(input: &str) -> String {
    let mut sanitized = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\x1b' => match chars.next() {
                Some('[') => consume_csi_sequence(&mut chars),
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    consume_string_control_sequence(&mut chars);
                }
                Some(_) | None => {}
            },
            '\u{9b}' => consume_csi_sequence(&mut chars),
            '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => {
                consume_string_control_sequence(&mut chars);
            }
            '\x00'..='\x08' | '\x0b'..='\x1f' | '\x7F' | '\u{80}'..='\u{9f}' => {
                // Filter out control characters that could be dangerous
            }
            '\t' | '\n' | ' '..='\x7e' | '\u{A0}'..=char::MAX => {
                sanitized.push(ch);
            }
        }
    }

    sanitized
}

fn consume_csi_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    for ch in chars.by_ref() {
        if matches!(ch, '\u{40}'..='\u{7e}') {
            break;
        }
    }
}

fn consume_string_control_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(ch) = chars.next() {
        if ch == '\x07' {
            break;
        }
        if ch == '\x1b' && chars.peek() == Some(&'\\') {
            chars.next();
            break;
        }
    }
}

pub trait Render {
    /// Render content into the output buffer.
    fn render(&self, out: &mut String, caps: &Capabilities, mode: ColorMode);
}

impl Render for Text {
    fn render(&self, out: &mut String, caps: &Capabilities, mode: ColorMode) {
        let emit_ansi = match mode {
            ColorMode::Never => false,
            ColorMode::Auto => caps.is_tty,
            ColorMode::Always => true,
        };
        let support = match mode {
            ColorMode::Never => ColorSupport::None,
            ColorMode::Auto => caps.color_support,
            ColorMode::Always => {
                if caps.color_support == ColorSupport::None {
                    ColorSupport::Basic
                } else {
                    caps.color_support
                }
            }
        };
        let sanitized = sanitize_ansi_escape_sequences(&self.content);
        self.style.render_to(out, &sanitized, support, emit_ansi);
    }
}

impl Render for str {
    fn render(&self, out: &mut String, _caps: &Capabilities, _mode: ColorMode) {
        out.push_str(&sanitize_ansi_escape_sequences(self));
    }
}

impl Render for String {
    fn render(&self, out: &mut String, caps: &Capabilities, mode: ColorMode) {
        self.as_str().render(out, caps, mode);
    }
}

/// Compute display width of a single character.
#[must_use]
pub fn char_width(ch: char) -> usize {
    if ch.is_ascii() {
        return 1;
    }
    if is_zero_width(ch) {
        return 0;
    }
    if is_combining(ch) {
        return 0;
    }
    if is_wide(ch) {
        return 2;
    }
    1
}

/// Compute display width of a string.
#[must_use]
pub fn str_width(value: &str) -> usize {
    let mut width = 0;
    let mut chars = value.chars().peekable();

    while let Some(ch) = chars.next() {
        if is_zero_width(ch) {
            continue;
        }

        if is_regional_indicator(ch) {
            if chars.peek().copied().is_some_and(is_regional_indicator) {
                let _ = chars.next();
                width += 2;
                continue;
            }

            width += char_width(ch);
            continue;
        }

        let mut cluster_width = char_width(ch);
        let mut cluster_tail = ch;
        let mut saw_joiner = false;
        let mut saw_emoji_modifier = false;
        let mut saw_emoji_presentation = false;
        let mut saw_keycap = false;

        while let Some(next) = chars.peek().copied() {
            if is_combining(next) {
                if next == '\u{20E3}' && is_keycap_base(ch) {
                    saw_keycap = true;
                }
                let _ = chars.next();
                continue;
            }

            if is_variation_selector(next) {
                if next == '\u{FE0F}' && is_emoji_presentation_candidate(cluster_tail) {
                    saw_emoji_presentation = true;
                }
                let _ = chars.next();
                continue;
            }

            if is_emoji_modifier(next) {
                saw_emoji_modifier = true;
                let _ = chars.next();
                continue;
            }

            if is_zero_width_joiner(next) {
                saw_joiner = true;
                let _ = chars.next();
                let Some(joined) = chars.next() else {
                    break;
                };
                cluster_width = cluster_width.max(char_width(joined));
                cluster_tail = joined;
                continue;
            }

            break;
        }

        if saw_keycap
            || (saw_emoji_presentation && is_emoji_presentation_candidate(cluster_tail))
            || (saw_emoji_modifier && is_emoji_presentation_candidate(cluster_tail))
            || (saw_joiner
                && (is_emoji_presentation_candidate(ch)
                    || is_emoji_presentation_candidate(cluster_tail)
                    || cluster_width == 2))
        {
            cluster_width = cluster_width.max(2);
        }

        width += cluster_width;
    }

    width
}

fn is_zero_width(ch: char) -> bool {
    is_zero_width_joiner(ch) || is_variation_selector(ch)
}

fn is_zero_width_joiner(ch: char) -> bool {
    ch == '\u{200D}'
}

fn is_variation_selector(ch: char) -> bool {
    matches!(ch as u32, 0xFE00..=0xFE0F | 0xE0100..=0xE01EF)
}

fn is_combining(ch: char) -> bool {
    matches!(
        ch as u32,
        0x0300..=0x036F
            | 0x1AB0..=0x1AFF
            | 0x1DC0..=0x1DFF
            | 0x20D0..=0x20FF
            | 0xFE20..=0xFE2F
    )
}

fn is_emoji_modifier(ch: char) -> bool {
    matches!(ch as u32, 0x1F3FB..=0x1F3FF)
}

fn is_regional_indicator(ch: char) -> bool {
    matches!(ch as u32, 0x1F1E6..=0x1F1FF)
}

fn is_emoji_presentation_candidate(ch: char) -> bool {
    matches!(ch as u32, 0x2600..=0x27BF | 0x1F000..=0x1FAFF)
}

fn is_keycap_base(ch: char) -> bool {
    ch.is_ascii_digit() || matches!(ch, '#' | '*')
}

fn is_wide(ch: char) -> bool {
    matches!(
        ch as u32,
        0x1100..=0x115F
            | 0x2329..=0x232A
            | 0x2E80..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE19
            | 0xFE30..=0xFE6F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1FAFF
    )
}

fn ansi_color_code(color: Color, support: ColorSupport, foreground: bool) -> Option<String> {
    match support {
        ColorSupport::None => None,
        ColorSupport::Basic => Some(basic_color_code(color, foreground)),
        ColorSupport::Extended => {
            let idx = color_to_ansi256(color);
            let prefix = if foreground { 38 } else { 48 };
            Some(format!("{prefix};5;{idx}"))
        }
        ColorSupport::TrueColor => match color {
            Color::Rgb(r, g, b) => {
                let prefix = if foreground { 38 } else { 48 };
                Some(format!("{prefix};2;{r};{g};{b}"))
            }
            Color::Index(idx) => {
                let prefix = if foreground { 38 } else { 48 };
                Some(format!("{prefix};5;{idx}"))
            }
            basic => Some(basic_color_code(basic, foreground)),
        },
    }
}

fn basic_color_code(color: Color, foreground: bool) -> String {
    let index = basic_color_index(color);
    let base = if foreground { 30 } else { 40 };
    let bright_base = if foreground { 90 } else { 100 };
    let code = if index < 8 {
        base + index
    } else {
        bright_base + (index - 8)
    };
    code.to_string()
}

fn basic_color_index(color: Color) -> u8 {
    match color {
        Color::Black => 0,
        Color::Red => 1,
        Color::Green => 2,
        Color::Yellow => 3,
        Color::Blue => 4,
        Color::Magenta => 5,
        Color::Cyan => 6,
        Color::White => 7,
        Color::BrightBlack => 8,
        Color::BrightRed => 9,
        Color::BrightGreen => 10,
        Color::BrightYellow => 11,
        Color::BrightBlue => 12,
        Color::BrightMagenta => 13,
        Color::BrightCyan => 14,
        Color::BrightWhite => 15,
        Color::Index(idx) => {
            if idx < 16 {
                idx
            } else {
                ansi256_to_basic(idx)
            }
        }
        Color::Rgb(r, g, b) => ansi256_to_basic(rgb_to_ansi256(r, g, b)),
    }
}

fn color_to_ansi256(color: Color) -> u8 {
    match color {
        Color::Index(idx) => idx,
        Color::Rgb(r, g, b) => rgb_to_ansi256(r, g, b),
        _ => basic_color_index(color),
    }
}

fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
    if r == g && g == b {
        return grayscale_to_ansi256(r);
    }
    let r = ((u16::from(r) * 5 + 127) / 255) as u8;
    let g = ((u16::from(g) * 5 + 127) / 255) as u8;
    let b = ((u16::from(b) * 5 + 127) / 255) as u8;
    16 + 36 * r + 6 * g + b
}

fn grayscale_to_ansi256(value: u8) -> u8 {
    if value < 8 {
        return 16;
    }
    if value > 247 {
        return 231;
    }
    232 + ((u16::from(value) - 8) / 10) as u8
}

fn ansi256_to_basic(idx: u8) -> u8 {
    if idx < 16 {
        return idx;
    }
    let (r, g, b) = ansi256_to_rgb(idx);
    let (bright, basic) = rgb_to_basic(r, g, b);
    if bright { basic + 8 } else { basic }
}

fn ansi256_to_rgb(idx: u8) -> (u8, u8, u8) {
    if idx < 16 {
        return basic_index_to_rgb(idx);
    }
    if idx >= 232 {
        let level = (idx - 232) * 10 + 8;
        return (level, level, level);
    }
    let idx = idx - 16;
    let r = idx / 36;
    let g = (idx % 36) / 6;
    let b = idx % 6;
    let r = (u16::from(r) * 255 / 5) as u8;
    let g = (u16::from(g) * 255 / 5) as u8;
    let b = (u16::from(b) * 255 / 5) as u8;
    (r, g, b)
}

fn basic_index_to_rgb(idx: u8) -> (u8, u8, u8) {
    match idx {
        0 => (0, 0, 0),
        1 => (205, 49, 49),
        2 => (13, 188, 121),
        3 => (229, 229, 16),
        4 => (36, 114, 200),
        5 => (188, 63, 188),
        6 => (17, 168, 205),
        7 => (229, 229, 229),
        8 => (102, 102, 102),
        9 => (241, 76, 76),
        10 => (35, 209, 139),
        11 => (245, 245, 67),
        12 => (59, 142, 234),
        13 => (214, 112, 214),
        14 => (41, 184, 219),
        _ => (255, 255, 255),
    }
}

fn rgb_to_basic(r: u8, g: u8, b: u8) -> (bool, u8) {
    let luminance = (u32::from(r) * 212 + u32::from(g) * 715 + u32::from(b) * 72) / 1000;
    let bright = luminance > 170;
    let (max, idx) = if r >= g && r >= b {
        (r, 1)
    } else if g >= r && g >= b {
        (g, 2)
    } else {
        (b, 4)
    };
    let base = if max < 32 { 0 } else { idx };
    (bright, base)
}

fn detect_unicode(env: &dyn Env) -> bool {
    let candidates = ["LC_ALL", "LC_CTYPE", "LANG"];
    for key in candidates {
        if let Some(value) = env.var(key) {
            let v = value.to_ascii_lowercase();
            if v.contains("utf-8") || v.contains("utf8") {
                return true;
            }
        }
    }
    false
}

fn size_from_env(env: &dyn Env) -> Option<(u16, u16)> {
    let width = env.var("COLUMNS").and_then(|v| v.parse::<u16>().ok());
    let height = env.var("LINES").and_then(|v| v.parse::<u16>().ok());
    match (width, height) {
        (Some(w), Some(h)) => Some((w, h)),
        _ => None,
    }
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

trait Env {
    fn var(&self, key: &str) -> Option<String>;
}

struct OsEnv;

impl Env for OsEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

#[cfg(test)]
#[path = "console_inline_tests.rs"]
mod tests;
