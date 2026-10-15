#![allow(missing_docs)]

#[macro_use]
mod common;

#[path = "e2e/console/mod.rs"]
mod console_e2e;

use asupersync::console::{Color, ColorMode, Text};
use console_e2e::util::{
    basic_color_caps, contains_ansi, extended_color_caps, full_color_caps, init_console_test,
    no_color_caps, strip_ansi, test_console,
};

#[test]
fn console_plain_text_never_mode_no_ansi() {
    init_console_test("console_plain_text_never_mode_no_ansi");
    let (console, writer) = test_console(no_color_caps(), ColorMode::Never);
    console.println(&Text::new("hello")).expect("println");
    let output = writer.output();
    assert_with_log!(
        !contains_ansi(&output),
        "no ansi",
        false,
        contains_ansi(&output)
    );
    assert_with_log!(output.trim_end() == "hello", "output", "hello", output);
    test_complete!("console_plain_text_never_mode_no_ansi");
}

#[test]
fn console_plain_text_auto_mode_no_tty() {
    init_console_test("console_plain_text_auto_mode_no_tty");
    let (console, writer) = test_console(no_color_caps(), ColorMode::Auto);
    console.println(&Text::new("plain")).expect("println");
    let output = writer.output();
    assert_with_log!(
        !contains_ansi(&output),
        "auto no tty",
        false,
        contains_ansi(&output)
    );
    assert_with_log!(output.trim_end() == "plain", "output", "plain", output);
    test_complete!("console_plain_text_auto_mode_no_tty");
}

#[test]
fn console_styled_text_auto_mode_tty_emits_ansi() {
    init_console_test("console_styled_text_auto_mode_tty_emits_ansi");
    let (console, writer) = test_console(full_color_caps(), ColorMode::Auto);
    console
        .println(&Text::new("hello").fg(Color::Green).bold())
        .expect("println");
    let output = writer.output();
    assert_with_log!(
        contains_ansi(&output),
        "ansi expected",
        true,
        contains_ansi(&output)
    );
    test_complete!("console_styled_text_auto_mode_tty_emits_ansi");
}

#[test]
fn console_always_mode_forces_ansi() {
    init_console_test("console_always_mode_forces_ansi");
    let (console, writer) = test_console(no_color_caps(), ColorMode::Always);
    console
        .println(&Text::new("forced").fg(Color::Red))
        .expect("println");
    let output = writer.output();
    assert_with_log!(
        contains_ansi(&output),
        "ansi forced",
        true,
        contains_ansi(&output)
    );
    test_complete!("console_always_mode_forces_ansi");
}

#[test]
fn console_clear_emits_ansi_when_enabled() {
    init_console_test("console_clear_emits_ansi_when_enabled");
    let (console, writer) = test_console(basic_color_caps(), ColorMode::Always);
    console.clear().expect("clear");
    let output = writer.output();
    assert_with_log!(
        contains_ansi(&output),
        "clear ansi",
        true,
        contains_ansi(&output)
    );
    test_complete!("console_clear_emits_ansi_when_enabled");
}

#[test]
fn console_clear_noop_when_disabled() {
    init_console_test("console_clear_noop_when_disabled");
    let (console, writer) = test_console(no_color_caps(), ColorMode::Never);
    console.clear().expect("clear");
    let output = writer.output();
    assert_with_log!(
        output.is_empty(),
        "clear no output",
        true,
        output.is_empty()
    );
    test_complete!("console_clear_noop_when_disabled");
}

#[test]
fn console_cursor_hide_show_emits_ansi() {
    init_console_test("console_cursor_hide_show_emits_ansi");
    let (console, writer) = test_console(extended_color_caps(), ColorMode::Always);
    console.cursor_hide().expect("hide");
    console.cursor_show().expect("show");
    let output = writer.output();
    assert_with_log!(
        contains_ansi(&output),
        "cursor ansi",
        true,
        contains_ansi(&output)
    );
    test_complete!("console_cursor_hide_show_emits_ansi");
}

#[test]
fn console_set_color_mode_changes_behavior() {
    init_console_test("console_set_color_mode_changes_behavior");
    let (mut console, writer) = test_console(no_color_caps(), ColorMode::Never);
    console
        .println(&Text::new("before").fg(Color::Blue))
        .expect("println");
    console.set_color_mode(ColorMode::Always);
    console
        .println(&Text::new("after").fg(Color::Blue))
        .expect("println");
    let output = writer.output();
    let ansi_count = output.matches("\x1b[").count();
    assert_with_log!(ansi_count >= 1, "ansi after switch", true, ansi_count >= 1);
    test_complete!("console_set_color_mode_changes_behavior");
}

#[test]
fn console_println_appends_newline() {
    init_console_test("console_println_appends_newline");
    let (console, writer) = test_console(full_color_caps(), ColorMode::Never);
    console.println(&Text::new("line")).expect("println");
    let output = writer.output();
    assert_with_log!(
        output.ends_with('\n'),
        "newline",
        true,
        output.ends_with('\n')
    );
    test_complete!("console_println_appends_newline");
}

#[test]
fn console_strip_ansi_returns_plain_text() {
    init_console_test("console_strip_ansi_returns_plain_text");
    let (console, writer) = test_console(full_color_caps(), ColorMode::Always);
    console
        .println(&Text::new("plain").fg(Color::Yellow).underline())
        .expect("println");
    let output = writer.output();
    let stripped = strip_ansi(&output);
    assert_with_log!(
        stripped.trim_end() == "plain",
        "strip ansi",
        "plain",
        stripped
    );
    test_complete!("console_strip_ansi_returns_plain_text");
}
