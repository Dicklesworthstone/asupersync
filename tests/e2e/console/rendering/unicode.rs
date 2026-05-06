//! Unicode width calculation E2E tests.

use crate::console_e2e::util::init_console_test;
use asupersync::console::{char_width, str_width};

#[test]
fn e2e_unicode_width_ascii() {
    init_console_test("e2e_unicode_width_ascii");

    // ASCII characters should all be width 1
    crate::assert_with_log!(char_width('A') == 1, "A width", 1usize, char_width('A'));
    crate::assert_with_log!(char_width('z') == 1, "z width", 1usize, char_width('z'));
    crate::assert_with_log!(char_width('0') == 1, "0 width", 1usize, char_width('0'));
    crate::assert_with_log!(char_width(' ') == 1, "space width", 1usize, char_width(' '));
    crate::assert_with_log!(char_width('!') == 1, "! width", 1usize, char_width('!'));

    crate::test_complete!("e2e_unicode_width_ascii");
}

#[test]
fn e2e_unicode_width_cjk() {
    init_console_test("e2e_unicode_width_cjk");

    // CJK characters should be width 2
    let chinese = '\u{4F60}'; // 你
    let japanese = '\u{3042}'; // あ
    let korean = '\u{AC00}'; // 가

    crate::assert_with_log!(
        char_width(chinese) == 2,
        "chinese width",
        2usize,
        char_width(chinese)
    );
    crate::assert_with_log!(
        char_width(japanese) == 2,
        "japanese width",
        2usize,
        char_width(japanese)
    );
    crate::assert_with_log!(
        char_width(korean) == 2,
        "korean width",
        2usize,
        char_width(korean)
    );

    crate::test_complete!("e2e_unicode_width_cjk");
}

#[test]
fn e2e_unicode_width_emoji() {
    init_console_test("e2e_unicode_width_emoji");

    // Emoji should be width 2
    let smiley = '\u{1F600}'; // 😀
    let heart = '\u{2764}'; // ❤ (not in the wide range)
    let sun = '\u{1F31E}'; // 🌞

    crate::assert_with_log!(
        char_width(smiley) == 2,
        "smiley width",
        2usize,
        char_width(smiley)
    );
    crate::assert_with_log!(
        char_width(heart) == 1,
        "heart width",
        1usize,
        char_width(heart)
    );
    crate::assert_with_log!(char_width(sun) == 2, "sun width", 2usize, char_width(sun));

    crate::test_complete!("e2e_unicode_width_emoji");
}

#[test]
fn e2e_unicode_width_combining() {
    init_console_test("e2e_unicode_width_combining");

    // Combining characters should be width 0
    let acute = '\u{0301}'; // combining acute accent
    let tilde = '\u{0303}'; // combining tilde
    let circumflex = '\u{0302}'; // combining circumflex

    crate::assert_with_log!(
        char_width(acute) == 0,
        "acute width",
        0usize,
        char_width(acute)
    );
    crate::assert_with_log!(
        char_width(tilde) == 0,
        "tilde width",
        0usize,
        char_width(tilde)
    );
    crate::assert_with_log!(
        char_width(circumflex) == 0,
        "circumflex width",
        0usize,
        char_width(circumflex)
    );

    crate::test_complete!("e2e_unicode_width_combining");
}

#[test]
fn e2e_unicode_str_width_ascii() {
    init_console_test("e2e_unicode_str_width_ascii");

    crate::assert_with_log!(
        str_width("hello") == 5,
        "hello width",
        5usize,
        str_width("hello")
    );
    crate::assert_with_log!(str_width("") == 0, "empty width", 0usize, str_width(""));
    crate::assert_with_log!(str_width("a") == 1, "a width", 1usize, str_width("a"));

    crate::test_complete!("e2e_unicode_str_width_ascii");
}

#[test]
fn e2e_unicode_str_width_mixed() {
    init_console_test("e2e_unicode_str_width_mixed");

    // Mix of ASCII and CJK
    let mixed = "hello\u{4F60}"; // hello你
    let expected = 5 + 2; // 5 ASCII + 1 CJK (width 2)
    crate::assert_with_log!(
        str_width(mixed) == expected,
        "mixed width",
        expected,
        str_width(mixed)
    );

    crate::test_complete!("e2e_unicode_str_width_mixed");
}

#[test]
fn e2e_unicode_str_width_with_combining() {
    init_console_test("e2e_unicode_str_width_with_combining");

    // 'e' with combining acute = width 1 (e=1, acute=0)
    let e_acute = "e\u{0301}";
    crate::assert_with_log!(
        str_width(e_acute) == 1,
        "e_acute width",
        1usize,
        str_width(e_acute)
    );

    // 'n' with combining tilde = width 1
    let n_tilde = "n\u{0303}";
    crate::assert_with_log!(
        str_width(n_tilde) == 1,
        "n_tilde width",
        1usize,
        str_width(n_tilde)
    );

    crate::test_complete!("e2e_unicode_str_width_with_combining");
}

#[test]
fn e2e_unicode_str_width_fullwidth() {
    init_console_test("e2e_unicode_str_width_fullwidth");

    // Fullwidth characters (FF00-FF60 range)
    let fullwidth_a = '\u{FF21}'; // Ａ (fullwidth A)
    crate::assert_with_log!(
        char_width(fullwidth_a) == 2,
        "fullwidth A",
        2usize,
        char_width(fullwidth_a)
    );

    crate::test_complete!("e2e_unicode_str_width_fullwidth");
}

#[test]
fn e2e_unicode_boundary_characters() {
    init_console_test("e2e_unicode_boundary_characters");

    // Test boundary conditions
    let hangul_start = '\u{AC00}'; // Start of Hangul syllables
    let hangul_end = '\u{D7A3}'; // End of Hangul syllables

    crate::assert_with_log!(
        char_width(hangul_start) == 2,
        "hangul start",
        2usize,
        char_width(hangul_start)
    );
    crate::assert_with_log!(
        char_width(hangul_end) == 2,
        "hangul end",
        2usize,
        char_width(hangul_end)
    );

    crate::test_complete!("e2e_unicode_boundary_characters");
}

#[test]
fn e2e_unicode_width_zero_width_scalars() {
    init_console_test("e2e_unicode_width_zero_width_scalars");

    crate::assert_with_log!(
        char_width('\u{200D}') == 0,
        "zwj width",
        0usize,
        char_width('\u{200D}')
    );
    crate::assert_with_log!(
        char_width('\u{FE0F}') == 0,
        "variation selector width",
        0usize,
        char_width('\u{FE0F}')
    );

    crate::test_complete!("e2e_unicode_width_zero_width_scalars");
}

#[test]
fn e2e_unicode_str_width_emoji_clusters() {
    init_console_test("e2e_unicode_str_width_emoji_clusters");

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

    crate::test_complete!("e2e_unicode_str_width_emoji_clusters");
}

#[test]
fn e2e_unicode_str_width_flag_pairs() {
    init_console_test("e2e_unicode_str_width_flag_pairs");

    crate::assert_with_log!(str_width("🇺🇸") == 2, "flag width", 2usize, str_width("🇺🇸"));

    crate::test_complete!("e2e_unicode_str_width_flag_pairs");
}
