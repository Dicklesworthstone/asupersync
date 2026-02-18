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

    /// Create a console that writes to the provided writer with auto-detected capabilities.
    #[must_use]
    pub fn with_writer<W: Write + Send + 'static>(writer: W) -> Self {
        let caps = Capabilities::detect_stdout();
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
    pub fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    /// Returns the current color mode.
    #[must_use]
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
        let is_tty = io::stdout().is_terminal();
        let env = OsEnv;
        let size = size_from_env(&env);
        Self::detect_from(&env, is_tty, size)
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
        if hex.len() != 6 {
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
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Access the style.
    #[must_use]
    pub fn style(&self) -> &Style {
        &self.style
    }
}

/// Renderable console content.
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
        self.style.render_to(out, &self.content, support, emit_ansi);
    }
}

impl Render for str {
    fn render(&self, out: &mut String, _caps: &Capabilities, _mode: ColorMode) {
        out.push_str(self);
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
    value.chars().map(char_width).sum()
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
    let luminance = (u16::from(r) * 212 + u16::from(g) * 715 + u16::from(b) * 72) / 1000;
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
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[derive(Default)]
    struct TestEnv {
        vars: HashMap<String, String>,
    }

    impl TestEnv {
        fn with(mut self, key: &str, value: &str) -> Self {
            self.vars.insert(key.to_string(), value.to_string());
            self
        }
    }

    impl Env for TestEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned()
        }
    }

    #[derive(Clone, Debug)]
    struct SharedWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
        flushes: Arc<AtomicUsize>,
    }

    impl SharedWriter {
        fn new() -> Self {
            Self {
                buffer: Arc::new(Mutex::new(Vec::new())),
                flushes: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn output(&self) -> String {
            String::from_utf8_lossy(&self.buffer.lock()).to_string()
        }
    }

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer.lock().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn detect_tty_stdout() {
        init_test("detect_tty_stdout");
        let caps = Capabilities::detect_stdout();
        crate::assert_with_log!(
            caps.is_tty == io::stdout().is_terminal(),
            "tty matches stdout",
            io::stdout().is_terminal(),
            caps.is_tty
        );
        crate::test_complete!("detect_tty_stdout");
    }

    #[test]
    fn detect_color_support_none() {
        init_test("detect_color_support_none");
        let env = TestEnv::default().with("NO_COLOR", "1");
        let support = ColorSupport::detect(&env, true);
        crate::assert_with_log!(
            support == ColorSupport::None,
            "no color",
            ColorSupport::None,
            support
        );
        crate::test_complete!("detect_color_support_none");
    }

    #[test]
    fn detect_color_support_basic() {
        init_test("detect_color_support_basic");
        let env = TestEnv::default().with("TERM", "xterm");
        let support = ColorSupport::detect(&env, true);
        crate::assert_with_log!(
            support == ColorSupport::Basic,
            "basic color",
            ColorSupport::Basic,
            support
        );
        crate::test_complete!("detect_color_support_basic");
    }

    #[test]
    fn detect_color_support_256() {
        init_test("detect_color_support_256");
        let env = TestEnv::default().with("TERM", "xterm-256color");
        let support = ColorSupport::detect(&env, true);
        crate::assert_with_log!(
            support == ColorSupport::Extended,
            "extended color",
            ColorSupport::Extended,
            support
        );
        crate::test_complete!("detect_color_support_256");
    }

    #[test]
    fn detect_color_support_true() {
        init_test("detect_color_support_true");
        let env = TestEnv::default().with("COLORTERM", "truecolor");
        let support = ColorSupport::detect(&env, true);
        crate::assert_with_log!(
            support == ColorSupport::TrueColor,
            "truecolor",
            ColorSupport::TrueColor,
            support
        );
        crate::test_complete!("detect_color_support_true");
    }

    #[test]
    fn detect_terminal_size_from_env() {
        init_test("detect_terminal_size_from_env");
        let env = TestEnv::default()
            .with("COLUMNS", "120")
            .with("LINES", "55");
        let caps = Capabilities::detect_from(&env, true, size_from_env(&env));
        crate::assert_with_log!(caps.width == 120, "width", 120u16, caps.width);
        crate::assert_with_log!(caps.height == 55, "height", 55u16, caps.height);
        crate::test_complete!("detect_terminal_size_from_env");
    }

    #[test]
    fn detect_unicode_support() {
        init_test("detect_unicode_support");
        let env = TestEnv::default().with("LANG", "en_US.UTF-8");
        let caps = Capabilities::detect_from(&env, true, Some((80, 24)));
        crate::assert_with_log!(caps.unicode, "unicode true", true, caps.unicode);
        crate::test_complete!("detect_unicode_support");
    }

    #[test]
    fn color_mode_auto() {
        init_test("color_mode_auto");
        let caps = Capabilities::detect_from(&TestEnv::default(), true, Some((80, 24)));
        let console = Console::with_caps(SharedWriter::new(), caps, ColorMode::Auto);
        crate::assert_with_log!(
            console.effective_color_support() != ColorSupport::None,
            "auto enables",
            true,
            console.effective_color_support() != ColorSupport::None
        );
        crate::test_complete!("color_mode_auto");
    }

    #[test]
    fn color_mode_force_never() {
        init_test("color_mode_force_never");
        let caps = Capabilities::detect_from(&TestEnv::default(), true, Some((80, 24)));
        let console = Console::with_caps(SharedWriter::new(), caps, ColorMode::Never);
        crate::assert_with_log!(
            console.effective_color_support() == ColorSupport::None,
            "never disables",
            ColorSupport::None,
            console.effective_color_support()
        );
        crate::test_complete!("color_mode_force_never");
    }

    #[test]
    fn style_escape_sequences() {
        init_test("style_escape_sequences");
        let text = Text::new("hi").fg(Color::Red).bold().underline();
        let mut buf = String::new();
        let caps = Capabilities {
            is_tty: true,
            color_support: ColorSupport::Basic,
            width: 80,
            height: 24,
            unicode: true,
        };
        text.render(&mut buf, &caps, ColorMode::Auto);
        crate::assert_with_log!(
            buf.contains("\x1b[1;4;31m"),
            "style code",
            true,
            buf.contains("\x1b[1;4;31m")
        );
        crate::assert_with_log!(
            buf.ends_with(ANSI_RESET),
            "reset code",
            true,
            buf.ends_with(ANSI_RESET)
        );
        crate::test_complete!("style_escape_sequences");
    }

    #[test]
    fn color_hex_parsing() {
        init_test("color_hex_parsing");
        let color = Color::from_hex("#FF00AA").expect("hex parse");
        crate::assert_with_log!(
            color == Color::Rgb(255, 0, 170),
            "hex rgb",
            Color::Rgb(255, 0, 170),
            color
        );
        crate::test_complete!("color_hex_parsing");
    }

    #[test]
    fn unicode_width_ascii() {
        init_test("unicode_width_ascii");
        crate::assert_with_log!(char_width('A') == 1, "A width", 1usize, 1usize);
        crate::test_complete!("unicode_width_ascii");
    }

    #[test]
    fn unicode_width_cjk() {
        init_test("unicode_width_cjk");
        let ch = char::from_u32(0x4F60).expect("char");
        crate::assert_with_log!(char_width(ch) == 2, "CJK width", 2usize, char_width(ch));
        crate::test_complete!("unicode_width_cjk");
    }

    #[test]
    fn unicode_width_emoji() {
        init_test("unicode_width_emoji");
        let ch = char::from_u32(0x1F600).expect("char");
        crate::assert_with_log!(char_width(ch) == 2, "emoji width", 2usize, char_width(ch));
        crate::test_complete!("unicode_width_emoji");
    }

    #[test]
    fn unicode_width_combining() {
        init_test("unicode_width_combining");
        let ch = char::from_u32(0x0301).expect("char");
        crate::assert_with_log!(
            char_width(ch) == 0,
            "combining width",
            0usize,
            char_width(ch)
        );
        crate::test_complete!("unicode_width_combining");
    }

    #[test]
    fn integration_print_styled() {
        init_test("integration_print_styled");
        let writer = SharedWriter::new();
        let caps = Capabilities {
            is_tty: true,
            color_support: ColorSupport::Basic,
            width: 80,
            height: 24,
            unicode: true,
        };
        let console = Console::with_caps(writer.clone(), caps, ColorMode::Auto);
        console
            .print(&Text::new("ok").fg(Color::Green))
            .expect("print");
        let output = writer.output();
        crate::assert_with_log!(
            output.contains("\x1b[32m"),
            "green code",
            true,
            output.contains("\x1b[32m")
        );
        crate::test_complete!("integration_print_styled");
    }

    #[test]
    fn integration_cursor_control() {
        init_test("integration_cursor_control");
        let writer = SharedWriter::new();
        let caps = Capabilities {
            is_tty: true,
            color_support: ColorSupport::Basic,
            width: 80,
            height: 24,
            unicode: true,
        };
        let console = Console::with_caps(writer.clone(), caps, ColorMode::Auto);
        console.cursor_hide().expect("hide");
        console.cursor_show().expect("show");
        let output = writer.output();
        crate::assert_with_log!(
            output.contains(ANSI_CURSOR_HIDE),
            "cursor hide",
            true,
            output.contains(ANSI_CURSOR_HIDE)
        );
        crate::assert_with_log!(
            output.contains(ANSI_CURSOR_SHOW),
            "cursor show",
            true,
            output.contains(ANSI_CURSOR_SHOW)
        );
        crate::test_complete!("integration_cursor_control");
    }

    #[test]
    fn integration_clear_screen() {
        init_test("integration_clear_screen");
        let writer = SharedWriter::new();
        let caps = Capabilities {
            is_tty: true,
            color_support: ColorSupport::Basic,
            width: 80,
            height: 24,
            unicode: true,
        };
        let console = Console::with_caps(writer.clone(), caps, ColorMode::Auto);
        console.clear().expect("clear");
        let output = writer.output();
        crate::assert_with_log!(
            output.contains(ANSI_CLEAR),
            "clear",
            true,
            output.contains(ANSI_CLEAR)
        );
        crate::test_complete!("integration_clear_screen");
    }
}
