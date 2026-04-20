#![no_main]

use arbitrary::Arbitrary;
use asupersync::net::dns::parse_resolv_conf_nameservers_for_test;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, SocketAddr};

const MAX_LINES: usize = 32;
const MAX_TOKEN_LEN: usize = 64;
const MAX_EXTRA_TOKENS: usize = 4;

#[derive(Debug, Arbitrary)]
struct ResolvConfFuzzInput {
    lines: Vec<ResolvConfLine>,
    trailing_newline: bool,
}

#[derive(Debug, Arbitrary)]
enum ResolvConfLine {
    Blank,
    Comment {
        prefix: CommentPrefix,
        body: String,
    },
    Nameserver {
        leading_spaces: u8,
        keyword: KeywordVariant,
        value: AddressVariant,
        extra_tokens: Vec<String>,
        trailing_comment: Option<CommentSuffix>,
    },
    Other {
        leading_spaces: u8,
        keyword: String,
        fields: Vec<String>,
        trailing_comment: Option<CommentSuffix>,
    },
    Raw(String),
}

#[derive(Debug, Arbitrary)]
enum CommentPrefix {
    Hash,
    Semicolon,
}

#[derive(Debug, Arbitrary)]
enum KeywordVariant {
    Nameserver,
    Uppercase,
    MixedCase,
}

#[derive(Debug, Arbitrary)]
enum AddressVariant {
    V4([u8; 4]),
    V6([u16; 8]),
    UnspecifiedV4,
    UnspecifiedV6,
    Token(String),
}

#[derive(Debug, Arbitrary)]
struct CommentSuffix {
    prefix: CommentPrefix,
    body: String,
}

fuzz_target!(|input: ResolvConfFuzzInput| {
    let rendered = render_resolv_conf(&input);
    let parsed = parse_resolv_conf_nameservers_for_test(&rendered);
    let expected = reference_parse_resolv_conf(&rendered);

    assert_eq!(
        parsed, expected,
        "resolv.conf parser diverged from reference parser for input:\n{rendered}"
    );

    let reparsed = parse_resolv_conf_nameservers_for_test(&rendered);
    assert_eq!(parsed, reparsed, "parser output must be deterministic");

    let normalized = format!("{rendered}\n");
    let normalized_parsed = parse_resolv_conf_nameservers_for_test(&normalized);
    assert_eq!(
        parsed, normalized_parsed,
        "appending a trailing newline must not change parser output"
    );
});

fn render_resolv_conf(input: &ResolvConfFuzzInput) -> String {
    let mut rendered = String::new();
    for (index, line) in input.lines.iter().take(MAX_LINES).enumerate() {
        if index != 0 {
            rendered.push('\n');
        }
        match line {
            ResolvConfLine::Blank => {}
            ResolvConfLine::Comment { prefix, body } => {
                rendered.push(comment_prefix_char(prefix));
                rendered.push_str(&sanitize_fragment(body));
            }
            ResolvConfLine::Nameserver {
                leading_spaces,
                keyword,
                value,
                extra_tokens,
                trailing_comment,
            } => {
                rendered.push_str(&" ".repeat((leading_spaces % 4) as usize));
                rendered.push_str(match keyword {
                    KeywordVariant::Nameserver => "nameserver",
                    KeywordVariant::Uppercase => "NAMESERVER",
                    KeywordVariant::MixedCase => "NameServer",
                });
                rendered.push(' ');
                rendered.push_str(&render_address(value));
                for token in extra_tokens.iter().take(MAX_EXTRA_TOKENS) {
                    let token = sanitize_token(token);
                    if !token.is_empty() {
                        rendered.push(' ');
                        rendered.push_str(&token);
                    }
                }
                if let Some(suffix) = trailing_comment {
                    rendered.push(' ');
                    rendered.push(comment_prefix_char(&suffix.prefix));
                    rendered.push_str(&sanitize_fragment(&suffix.body));
                }
            }
            ResolvConfLine::Other {
                leading_spaces,
                keyword,
                fields,
                trailing_comment,
            } => {
                rendered.push_str(&" ".repeat((leading_spaces % 4) as usize));
                let keyword = sanitize_token(keyword);
                if keyword.is_empty() {
                    rendered.push('x');
                } else {
                    rendered.push_str(&keyword);
                }
                for field in fields.iter().take(MAX_EXTRA_TOKENS) {
                    let field = sanitize_token(field);
                    if !field.is_empty() {
                        rendered.push(' ');
                        rendered.push_str(&field);
                    }
                }
                if let Some(suffix) = trailing_comment {
                    rendered.push(' ');
                    rendered.push(comment_prefix_char(&suffix.prefix));
                    rendered.push_str(&sanitize_fragment(&suffix.body));
                }
            }
            ResolvConfLine::Raw(raw) => {
                rendered.push_str(&sanitize_fragment(raw));
            }
        }
    }
    if input.trailing_newline {
        rendered.push('\n');
    }
    rendered
}

fn render_address(value: &AddressVariant) -> String {
    match value {
        AddressVariant::V4(octets) => IpAddr::from(*octets).to_string(),
        AddressVariant::V6(segments) => IpAddr::from(*segments).to_string(),
        AddressVariant::UnspecifiedV4 => "0.0.0.0".to_string(),
        AddressVariant::UnspecifiedV6 => "::".to_string(),
        AddressVariant::Token(raw) => sanitize_token(raw),
    }
}

fn reference_parse_resolv_conf(contents: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();

    for raw_line in contents.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }

        let Some(value) = fields.next() else {
            continue;
        };
        let Ok(ip) = value.parse::<IpAddr>() else {
            continue;
        };
        if ip.is_unspecified() {
            continue;
        }

        let addr = SocketAddr::new(ip, 53);
        if !out.contains(&addr) {
            out.push(addr);
        }
    }

    out
}

fn strip_comment(line: &str) -> &str {
    match (line.find('#'), line.find(';')) {
        (Some(hash), Some(semicolon)) => &line[..hash.min(semicolon)],
        (Some(hash), None) => &line[..hash],
        (None, Some(semicolon)) => &line[..semicolon],
        (None, None) => line,
    }
}

fn sanitize_fragment(raw: &str) -> String {
    raw.chars()
        .filter(|ch| !matches!(ch, '\n' | '\r'))
        .take(MAX_TOKEN_LEN)
        .collect()
}

fn sanitize_token(raw: &str) -> String {
    sanitize_fragment(raw)
        .chars()
        .map(|ch| if ch.is_whitespace() { '_' } else { ch })
        .collect()
}

fn comment_prefix_char(prefix: &CommentPrefix) -> char {
    match prefix {
        CommentPrefix::Hash => '#',
        CommentPrefix::Semicolon => ';',
    }
}
