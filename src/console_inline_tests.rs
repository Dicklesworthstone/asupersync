    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::collections::HashMap;
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempfile;

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
    fn with_writer_uses_target_stream_capabilities() {
        init_test("with_writer_uses_target_stream_capabilities");
        let writer = tempfile().expect("tempfile");
        let mut reader = writer.try_clone().expect("clone tempfile");
        let console = Console::with_writer(writer);
        crate::assert_with_log!(
            !console.capabilities().is_tty,
            "tempfile is non-terminal",
            false,
            console.capabilities().is_tty
        );
        crate::assert_with_log!(
            console.capabilities().color_support == ColorSupport::None,
            "non-terminal disables color",
            ColorSupport::None,
            console.capabilities().color_support
        );
        console
            .print(&Text::new("ok").fg(Color::Green))
            .expect("print");
        drop(console);
        reader.seek(SeekFrom::Start(0)).expect("rewind");
        let mut output = String::new();
        reader.read_to_string(&mut output).expect("read output");
        crate::assert_with_log!(output == "ok", "plain output", "ok", output.as_str());
        crate::test_complete!("with_writer_uses_target_stream_capabilities");
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
    fn unicode_width_zero_width_scalars() {
        init_test("unicode_width_zero_width_scalars");
        crate::assert_with_log!(
            char_width('\u{200D}') == 0,
            "zwj width",
            0usize,
            char_width('\u{200D}')
        );
        crate::assert_with_log!(
            char_width('\u{FE0F}') == 0,
            "vs16 width",
            0usize,
            char_width('\u{FE0F}')
        );
        crate::test_complete!("unicode_width_zero_width_scalars");
    }

    #[test]
    fn unicode_str_width_emoji_clusters() {
        init_test("unicode_str_width_emoji_clusters");
        crate::assert_with_log!(
            str_width("👨‍👩‍👧‍👦") == 2,
            "family emoji width",
            2usize,
            str_width("👨‍👩‍👧‍👦")
        );
        crate::assert_with_log!(
            str_width("❤️") == 2,
            "heart emoji width",
            2usize,
            str_width("❤️")
        );
        crate::assert_with_log!(
            str_width("1️⃣") == 2,
            "keycap width",
            2usize,
            str_width("1️⃣")
        );
        crate::test_complete!("unicode_str_width_emoji_clusters");
    }

    #[test]
    fn unicode_str_width_flag_pair() {
        init_test("unicode_str_width_flag_pair");
        crate::assert_with_log!(str_width("🇺🇸") == 2, "flag width", 2usize, str_width("🇺🇸"));
        crate::test_complete!("unicode_str_width_flag_pair");
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

    // Pure data-type tests (wave 36 – CyanBarn)

    #[test]
    fn capabilities_debug_copy() {
        let caps = Capabilities {
            is_tty: false,
            color_support: ColorSupport::Extended,
            width: 120,
            height: 40,
            unicode: true,
        };
        let dbg = format!("{caps:?}");
        assert!(dbg.contains("Capabilities"));

        // Copy
        let caps2 = caps;
        assert_eq!(caps, caps2);
        assert_eq!(caps2.width, 120);
        assert_eq!(caps2.height, 40);

        // Clone
        let caps3 = caps;
        assert_eq!(caps, caps3);
    }

    #[test]
    fn color_mode_debug_copy_eq() {
        let modes = [ColorMode::Auto, ColorMode::Always, ColorMode::Never];
        for mode in &modes {
            let dbg = format!("{mode:?}");
            assert!(!dbg.is_empty());

            // Copy
            let m2 = *mode;
            assert_eq!(*mode, m2);
        }
        assert_ne!(ColorMode::Auto, ColorMode::Always);
        assert_ne!(ColorMode::Always, ColorMode::Never);
    }

    #[test]
    fn color_support_debug_copy_eq() {
        let variants = [
            ColorSupport::None,
            ColorSupport::Basic,
            ColorSupport::Extended,
            ColorSupport::TrueColor,
        ];
        for v in &variants {
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());
            let v2 = *v;
            assert_eq!(*v, v2);
        }
        assert_ne!(ColorSupport::None, ColorSupport::Basic);
        assert_ne!(ColorSupport::Extended, ColorSupport::TrueColor);
    }

    #[test]
    fn color_debug_copy() {
        let colors = [
            Color::Black,
            Color::Red,
            Color::Green,
            Color::Blue,
            Color::BrightCyan,
            Color::Index(42),
            Color::Rgb(10, 20, 30),
        ];
        for color in &colors {
            let dbg = format!("{color:?}");
            assert!(!dbg.is_empty());
            let c2 = *color;
            assert_eq!(*color, c2);
        }
    }

    #[test]
    fn style_debug_clone_copy_default() {
        let default_style = Style::default();
        assert!(default_style.fg.is_none());
        assert!(default_style.bg.is_none());
        assert!(!default_style.bold);
        assert!(!default_style.italic);
        assert!(!default_style.underline);
        assert!(!default_style.dim);

        let dbg = format!("{default_style:?}");
        assert!(dbg.contains("Style"));

        // Builder
        let styled = Style::new()
            .fg(Color::Red)
            .bold()
            .italic()
            .underline()
            .dim();
        assert_eq!(styled.fg, Some(Color::Red));
        assert!(styled.bold);
        assert!(styled.italic);
        assert!(styled.underline);
        assert!(styled.dim);

        // Copy
        let styled2 = styled;
        assert_eq!(styled, styled2);

        // Clone
        let styled3 = styled;
        assert_eq!(styled, styled3);
    }

    #[test]
    fn text_debug_clone_eq() {
        let text = Text::new("hello").fg(Color::Green).bold();
        let dbg = format!("{text:?}");
        assert!(dbg.contains("Text"));

        assert_eq!(text.content(), "hello");
        assert_eq!(text.style().fg, Some(Color::Green));
        assert!(text.style().bold);

        let cloned = text.clone();
        assert_eq!(text, cloned);
        assert_eq!(cloned.content(), "hello");
    }

    #[test]
    fn console_debug() {
        let caps = Capabilities {
            is_tty: false,
            color_support: ColorSupport::None,
            width: 80,
            height: 24,
            unicode: false,
        };
        let console = Console::with_caps(SharedWriter::new(), caps, ColorMode::Never);
        let dbg = format!("{console:?}");
        assert!(dbg.contains("Console"));
    }

    /// Test ANSI injection attack prevention.
    ///
    /// **Security Test**: Verifies that malicious ANSI escape sequences in user-provided
    /// content are properly sanitized and cannot manipulate the terminal.
    #[test]
    fn ansi_injection_prevention() {
        // Test various ANSI injection attacks
        let malicious_inputs = [
            ("\x1b[2J\x1b[H", ""),                           // Clear screen and home cursor
            ("\x1b[31mRED TEXT\x1b[0m", "RED TEXT"),         // Color injection
            ("Hello\x1b[1000D\x1b[KEvil", "HelloEvil"),      // Cursor movement + line clear
            ("\x1b]0;Forged Title\x07", ""),                 // Terminal title manipulation
            ("\x1b]0;Forged Title\x1b\\Visible", "Visible"), // OSC terminated by ST
            ("\x1b[?25l\x1b[?25h", ""),                      // Hide/show cursor
            ("\x1b[s\x1b[u", ""),                            // Save/restore cursor
            ("Normal\x1b[3J\x1b[1;1HEvil", "NormalEvil"),    // Clear all + position
            (
                "\x1b[2K\rOverwrite previous line",
                "Overwrite previous line",
            ),
            ("\u{9b}31mRED\u{9b}0m", "RED"), // UTF-8 C1 CSI form
        ];

        for (i, (malicious_input, expected)) in malicious_inputs.iter().enumerate() {
            let sanitized = sanitize_ansi_escape_sequences(malicious_input);

            // Verify no ANSI escape sequences made it through
            assert!(
                !sanitized.contains('\x1b'),
                "Test case {}: ANSI escape sequences not filtered from: {:?}",
                i,
                malicious_input
            );

            assert_eq!(
                sanitized, *expected,
                "Test case {i}: sanitized content mismatch"
            );
        }

        // Test that legitimate content is preserved
        let legitimate_inputs = [
            "Hello, World!",
            "Multi\nLine\nText",
            "Tabs\tand\tspaces work fine",
            "Symbols: !@#$%^&*()_+-=[]{}|;':\",./<>?",
        ];

        for legitimate_input in &legitimate_inputs {
            let sanitized = sanitize_ansi_escape_sequences(legitimate_input);

            // Legitimate content should be preserved exactly
            assert_eq!(
                sanitized, *legitimate_input,
                "Legitimate content was incorrectly filtered: {:?}",
                legitimate_input
            );
        }

        crate::test_complete!("ansi_injection_prevention");
    }

    #[test]
    fn styled_text_sanitizes_user_escape_sequences() {
        init_test("styled_text_sanitizes_user_escape_sequences");

        let caps = Capabilities {
            is_tty: true,
            color_support: ColorSupport::Basic,
            width: 80,
            height: 24,
            unicode: true,
        };
        let text = Text::new("\x1b]0;Forged Title\x07hello\x1b[31mred\x1b[0m").fg(Color::Red);
        let mut buf = String::new();
        text.render(&mut buf, &caps, ColorMode::Always);

        assert_eq!(
            buf, "\x1b[31mhellored\x1b[0m",
            "styled rendering may emit its own ANSI wrapper but must sanitize user content"
        );

        crate::test_complete!("styled_text_sanitizes_user_escape_sequences");
    }
