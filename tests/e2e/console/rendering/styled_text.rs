//! Styled text rendering E2E tests.

use crate::console_e2e::util::{
    basic_color_caps, contains_ansi, init_console_test, strip_ansi, test_console,
};
use asupersync::console::{Color, ColorMode, Text};

#[test]
fn e2e_styled_text_bold() {
    init_console_test("e2e_styled_text_bold");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);
    let text = Text::new("bold text").bold();
    console.println(&text).expect("print");
    let output = writer.output();

    // Bold is SGR code 1
    crate::assert_with_log!(
        output.contains("\x1b[1m") || output.contains(";1m") || output.contains("[1;"),
        "bold code",
        true,
        output.contains("1")
    );

    crate::test_complete!("e2e_styled_text_bold");
}

#[test]
fn e2e_styled_text_italic() {
    init_console_test("e2e_styled_text_italic");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);
    let text = Text::new("italic text").italic();
    console.println(&text).expect("print");
    let output = writer.output();

    // Italic is SGR code 3
    crate::assert_with_log!(
        output.contains("\x1b[3m") || output.contains(";3m") || output.contains(";3;"),
        "italic code",
        true,
        contains_ansi(&output)
    );

    crate::test_complete!("e2e_styled_text_italic");
}

#[test]
fn e2e_styled_text_underline() {
    init_console_test("e2e_styled_text_underline");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);
    let text = Text::new("underlined").underline();
    console.println(&text).expect("print");
    let output = writer.output();

    // Underline is SGR code 4
    crate::assert_with_log!(
        output.contains("\x1b[4m") || output.contains(";4m") || output.contains(";4;"),
        "underline code",
        true,
        contains_ansi(&output)
    );

    crate::test_complete!("e2e_styled_text_underline");
}

#[test]
fn e2e_styled_text_dim() {
    init_console_test("e2e_styled_text_dim");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);
    let text = Text::new("dimmed").dim();
    console.println(&text).expect("print");
    let output = writer.output();

    // Dim is SGR code 2
    crate::assert_with_log!(
        output.contains("\x1b[2m") || output.contains(";2m") || output.contains(";2;"),
        "dim code",
        true,
        contains_ansi(&output)
    );

    crate::test_complete!("e2e_styled_text_dim");
}

#[test]
fn e2e_styled_text_combined_styles() {
    init_console_test("e2e_styled_text_combined_styles");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);
    let text = Text::new("styled").fg(Color::Red).bold().underline();
    console.println(&text).expect("print");
    let output = writer.output();

    // Should have bold (1), underline (4), and red (31)
    crate::assert_with_log!(output.contains('1'), "has bold", true, output.contains('1'));
    crate::assert_with_log!(
        output.contains('4'),
        "has underline",
        true,
        output.contains('4')
    );
    crate::assert_with_log!(
        output.contains("31"),
        "has red",
        true,
        output.contains("31")
    );

    crate::test_complete!("e2e_styled_text_combined_styles");
}

#[test]
fn e2e_styled_text_reset_at_end() {
    init_console_test("e2e_styled_text_reset_at_end");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);
    let text = Text::new("styled").fg(Color::Green).bold();
    console.println(&text).expect("print");
    let output = writer.output();

    // Should end with reset code \x1b[0m
    let stripped = output.trim_end_matches('\n');
    crate::assert_with_log!(
        stripped.ends_with("\x1b[0m"),
        "ends with reset",
        true,
        stripped.ends_with("\x1b[0m")
    );

    crate::test_complete!("e2e_styled_text_reset_at_end");
}

#[test]
fn e2e_styled_text_plain_no_codes() {
    init_console_test("e2e_styled_text_plain_no_codes");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);
    let text = Text::new("plain text");
    console.println(&text).expect("print");
    let output = writer.output();

    // Plain text should have no ANSI codes
    crate::assert_with_log!(
        !contains_ansi(&output),
        "no ansi for plain",
        false,
        contains_ansi(&output)
    );
    crate::assert_with_log!(
        output.contains("plain text"),
        "content present",
        true,
        output.contains("plain text")
    );

    crate::test_complete!("e2e_styled_text_plain_no_codes");
}

#[test]
fn e2e_styled_text_strip_ansi() {
    init_console_test("e2e_styled_text_strip_ansi");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);
    let text = Text::new("visible").fg(Color::Blue).bold().underline();
    console.println(&text).expect("print");
    let output = writer.output();

    // Strip should give us just the content
    let stripped = strip_ansi(&output);
    crate::assert_with_log!(
        stripped.trim() == "visible",
        "stripped content",
        "visible",
        stripped.trim()
    );
    crate::assert_with_log!(
        !contains_ansi(&stripped),
        "no ansi after strip",
        false,
        contains_ansi(&stripped)
    );

    crate::test_complete!("e2e_styled_text_strip_ansi");
}

#[test]
fn e2e_styled_text_hex_color() {
    init_console_test("e2e_styled_text_hex_color");

    let color = Color::from_hex("#FF00FF").expect("parse hex");
    crate::assert_with_log!(
        color == Color::Rgb(255, 0, 255),
        "hex parsing",
        Color::Rgb(255, 0, 255),
        color
    );

    let (console, writer) =
        test_console(crate::console_e2e::util::full_color_caps(), ColorMode::Auto);
    let text = Text::new("magenta").fg(color);
    console.println(&text).expect("print");
    let output = writer.output();

    crate::assert_with_log!(
        output.contains("38;2;255;0;255"),
        "hex rgb code",
        true,
        output.contains("38;2;255;0;255")
    );

    crate::test_complete!("e2e_styled_text_hex_color");
}

#[test]
fn e2e_styled_text_fg_and_bg() {
    init_console_test("e2e_styled_text_fg_and_bg");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);
    let text = Text::new("contrast").fg(Color::White).bg(Color::Blue);
    console.println(&text).expect("print");
    let output = writer.output();

    // White fg is 37, Blue bg is 44
    crate::assert_with_log!(
        output.contains("37"),
        "white fg",
        true,
        output.contains("37")
    );
    crate::assert_with_log!(
        output.contains("44"),
        "blue bg",
        true,
        output.contains("44")
    );

    crate::test_complete!("e2e_styled_text_fg_and_bg");
}
