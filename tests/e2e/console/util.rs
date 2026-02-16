//! Shared helpers for Console E2E tests.

#![allow(dead_code)]

use asupersync::console::{Capabilities, ColorMode, ColorSupport, Console};
use parking_lot::Mutex;
use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Initialize a console test with logging.
pub fn init_console_test(test_name: &str) {
    crate::common::init_test_logging();
    crate::test_phase!(test_name);
}

/// A test writer that captures output for verification.
#[derive(Clone, Debug)]
pub struct TestWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
    flushes: Arc<AtomicUsize>,
}

impl TestWriter {
    /// Create a new test writer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::new())),
            flushes: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Get the captured output as a string.
    #[must_use]
    pub fn output(&self) -> String {
        String::from_utf8_lossy(&self.buffer.lock()).to_string()
    }

    /// Get the raw captured bytes.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.buffer.lock().clone()
    }

    /// Get the number of flushes.
    #[must_use]
    pub fn flush_count(&self) -> usize {
        self.flushes.load(Ordering::Relaxed)
    }

    /// Clear the buffer.
    pub fn clear(&self) {
        self.buffer.lock().clear();
    }
}

impl Default for TestWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// Create test capabilities with full color support.
#[must_use]
pub fn full_color_caps() -> Capabilities {
    Capabilities {
        is_tty: true,
        color_support: ColorSupport::TrueColor,
        width: 120,
        height: 40,
        unicode: true,
    }
}

/// Create test capabilities with basic (16-color) support.
#[must_use]
pub fn basic_color_caps() -> Capabilities {
    Capabilities {
        is_tty: true,
        color_support: ColorSupport::Basic,
        width: 80,
        height: 24,
        unicode: true,
    }
}

/// Create test capabilities with 256-color support.
#[must_use]
pub fn extended_color_caps() -> Capabilities {
    Capabilities {
        is_tty: true,
        color_support: ColorSupport::Extended,
        width: 100,
        height: 30,
        unicode: true,
    }
}

/// Create test capabilities with no color support (dumb terminal).
#[must_use]
pub fn no_color_caps() -> Capabilities {
    Capabilities {
        is_tty: false,
        color_support: ColorSupport::None,
        width: 80,
        height: 24,
        unicode: false,
    }
}

/// Create a console for testing with a captured writer.
#[must_use]
pub fn test_console(caps: Capabilities, mode: ColorMode) -> (Console, TestWriter) {
    let writer = TestWriter::new();
    let console = Console::with_caps(writer.clone(), caps, mode);
    (console, writer)
}

/// Check if output contains an ANSI escape sequence.
#[must_use]
pub fn contains_ansi(output: &str) -> bool {
    output.contains("\x1b[")
}

/// Count ANSI escape sequences in output.
#[must_use]
pub fn count_ansi_sequences(output: &str) -> usize {
    output.matches("\x1b[").count()
}

/// Strip all ANSI escape sequences from output.
#[must_use]
pub fn strip_ansi(output: &str) -> String {
    let mut result = String::new();
    let mut chars = output.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Skip the escape sequence
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                              // Skip until we hit a letter (the terminal code)
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}
