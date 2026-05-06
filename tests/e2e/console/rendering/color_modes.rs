//! Color mode E2E tests.

use crate::console_e2e::util::{
    basic_color_caps, contains_ansi, full_color_caps, init_console_test, no_color_caps,
    test_console,
};
use asupersync::console::{Color, ColorMode, Text};

#[test]
fn e2e_color_mode_auto_respects_tty() {
    init_console_test("e2e_color_mode_auto_respects_tty");

    // Auto mode with TTY should emit colors
    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);
    let text = Text::new("colored").fg(Color::Green);
    console.println(&text).expect("print");
    let output = writer.output();

    crate::assert_with_log!(
        contains_ansi(&output),
        "auto tty has ansi",
        true,
        contains_ansi(&output)
    );

    // Auto mode without TTY should not emit colors
    let (console, writer) = test_console(no_color_caps(), ColorMode::Auto);
    console.println(&text).expect("print");
    let output = writer.output();

    crate::assert_with_log!(
        !contains_ansi(&output),
        "auto no-tty no ansi",
        false,
        contains_ansi(&output)
    );

    crate::test_complete!("e2e_color_mode_auto_respects_tty");
}

#[test]
fn e2e_color_mode_always_forces_color() {
    init_console_test("e2e_color_mode_always_forces_color");

    // Always mode should emit colors even without TTY
    let (console, writer) = test_console(no_color_caps(), ColorMode::Always);
    let text = Text::new("forced").fg(Color::Blue);
    console.println(&text).expect("print");
    let output = writer.output();

    crate::assert_with_log!(
        contains_ansi(&output),
        "always has ansi",
        true,
        contains_ansi(&output)
    );

    crate::test_complete!("e2e_color_mode_always_forces_color");
}

#[test]
fn e2e_color_mode_never_suppresses_color() {
    init_console_test("e2e_color_mode_never_suppresses_color");

    // Never mode should not emit colors even with TTY
    let (console, writer) = test_console(full_color_caps(), ColorMode::Never);
    let text = Text::new("plain").fg(Color::Red).bold();
    console.println(&text).expect("print");
    let output = writer.output();

    crate::assert_with_log!(
        !contains_ansi(&output),
        "never no ansi",
        false,
        contains_ansi(&output)
    );

    // Content should still be there
    crate::assert_with_log!(
        output.contains("plain"),
        "content present",
        true,
        output.contains("plain")
    );

    crate::test_complete!("e2e_color_mode_never_suppresses_color");
}

#[test]
fn e2e_color_mode_basic_16_colors() {
    init_console_test("e2e_color_mode_basic_16_colors");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);

    // Basic colors should use SGR 30-37 / 90-97
    let colors = [
        (Color::Black, "30"),
        (Color::Red, "31"),
        (Color::Green, "32"),
        (Color::Yellow, "33"),
        (Color::Blue, "34"),
        (Color::Magenta, "35"),
        (Color::Cyan, "36"),
        (Color::White, "37"),
        (Color::BrightRed, "91"),
        (Color::BrightGreen, "92"),
    ];

    for (color, expected_code) in colors {
        writer.clear();
        let text = Text::new("test").fg(color);
        console.println(&text).expect("print");
        let output = writer.output();

        crate::assert_with_log!(
            output.contains(expected_code),
            "color code present",
            true,
            output.contains(expected_code)
        );
    }

    crate::test_complete!("e2e_color_mode_basic_16_colors");
}

#[test]
fn e2e_color_mode_256_colors() {
    init_console_test("e2e_color_mode_256_colors");

    let caps = crate::console_e2e::util::extended_color_caps();
    let (console, writer) = test_console(caps, ColorMode::Auto);

    // 256-color mode should use SGR 38;5;N format
    let text = Text::new("indexed").fg(Color::Index(42));
    console.println(&text).expect("print");
    let output = writer.output();

    crate::assert_with_log!(
        output.contains("38;5;42"),
        "256 color code",
        true,
        output.contains("38;5;42")
    );

    crate::test_complete!("e2e_color_mode_256_colors");
}

#[test]
fn e2e_color_mode_truecolor_rgb() {
    init_console_test("e2e_color_mode_truecolor_rgb");

    let (console, writer) = test_console(full_color_caps(), ColorMode::Auto);

    // True color should use SGR 38;2;R;G;B format
    let text = Text::new("rgb").fg(Color::Rgb(255, 128, 64));
    console.println(&text).expect("print");
    let output = writer.output();

    crate::assert_with_log!(
        output.contains("38;2;255;128;64"),
        "truecolor code",
        true,
        output.contains("38;2;255;128;64")
    );

    crate::test_complete!("e2e_color_mode_truecolor_rgb");
}

#[test]
fn e2e_color_mode_background_colors() {
    init_console_test("e2e_color_mode_background_colors");

    let (console, writer) = test_console(basic_color_caps(), ColorMode::Auto);

    // Background colors should use SGR 40-47
    let text = Text::new("bg").bg(Color::Red);
    console.println(&text).expect("print");
    let output = writer.output();

    // Red background is code 41
    crate::assert_with_log!(
        output.contains("41"),
        "bg color code",
        true,
        output.contains("41")
    );

    crate::test_complete!("e2e_color_mode_background_colors");
}
