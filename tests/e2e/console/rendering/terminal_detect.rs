//! Terminal capability detection E2E tests.

use crate::console_e2e::util::{
    basic_color_caps, extended_color_caps, full_color_caps, init_console_test, no_color_caps,
    test_console,
};
use asupersync::console::{Capabilities, ColorMode, ColorSupport, Text};

#[test]
fn e2e_terminal_detect_tty_flag() {
    init_console_test("e2e_terminal_detect_tty_flag");

    let tty_caps = Capabilities {
        is_tty: true,
        color_support: ColorSupport::Basic,
        width: 80,
        height: 24,
        unicode: true,
    };

    let non_tty_caps = Capabilities {
        is_tty: false,
        color_support: ColorSupport::Basic,
        width: 80,
        height: 24,
        unicode: true,
    };

    let (tty_console, tty_writer) = test_console(tty_caps, ColorMode::Auto);
    let (non_tty_console, non_tty_writer) = test_console(non_tty_caps, ColorMode::Auto);

    // Print styled text to both
    let text = Text::new("test").fg(asupersync::console::Color::Red);
    tty_console.println(&text).expect("print");
    non_tty_console.println(&text).expect("print");

    let tty_output = tty_writer.output();
    let non_tty_output = non_tty_writer.output();

    // TTY should have ANSI codes, non-TTY should not (in Auto mode)
    crate::assert_with_log!(
        tty_output.contains("\x1b["),
        "tty has ansi",
        true,
        tty_output.contains("\x1b[")
    );
    crate::assert_with_log!(
        !non_tty_output.contains("\x1b["),
        "non-tty no ansi",
        false,
        non_tty_output.contains("\x1b[")
    );

    crate::test_complete!("e2e_terminal_detect_tty_flag");
}

#[test]
fn e2e_terminal_detect_color_support_levels() {
    init_console_test("e2e_terminal_detect_color_support_levels");

    let none = no_color_caps();
    let basic = basic_color_caps();
    let extended = extended_color_caps();
    let truecolor = full_color_caps();

    crate::assert_with_log!(
        none.color_support == ColorSupport::None,
        "no color",
        ColorSupport::None,
        none.color_support
    );
    crate::assert_with_log!(
        basic.color_support == ColorSupport::Basic,
        "basic color",
        ColorSupport::Basic,
        basic.color_support
    );
    crate::assert_with_log!(
        extended.color_support == ColorSupport::Extended,
        "extended color",
        ColorSupport::Extended,
        extended.color_support
    );
    crate::assert_with_log!(
        truecolor.color_support == ColorSupport::TrueColor,
        "truecolor",
        ColorSupport::TrueColor,
        truecolor.color_support
    );

    crate::test_complete!("e2e_terminal_detect_color_support_levels");
}

#[test]
fn e2e_terminal_detect_dimensions() {
    init_console_test("e2e_terminal_detect_dimensions");

    let caps = Capabilities {
        is_tty: true,
        color_support: ColorSupport::Basic,
        width: 120,
        height: 40,
        unicode: true,
    };

    crate::assert_with_log!(caps.width == 120, "width", 120u16, caps.width);
    crate::assert_with_log!(caps.height == 40, "height", 40u16, caps.height);

    crate::test_complete!("e2e_terminal_detect_dimensions");
}

#[test]
fn e2e_terminal_detect_unicode_flag() {
    init_console_test("e2e_terminal_detect_unicode_flag");

    let unicode_caps = Capabilities {
        is_tty: true,
        color_support: ColorSupport::Basic,
        width: 80,
        height: 24,
        unicode: true,
    };

    let ascii_caps = Capabilities {
        is_tty: true,
        color_support: ColorSupport::Basic,
        width: 80,
        height: 24,
        unicode: false,
    };

    crate::assert_with_log!(
        unicode_caps.unicode,
        "unicode true",
        true,
        unicode_caps.unicode
    );
    crate::assert_with_log!(
        !ascii_caps.unicode,
        "unicode false",
        false,
        ascii_caps.unicode
    );

    crate::test_complete!("e2e_terminal_detect_unicode_flag");
}
