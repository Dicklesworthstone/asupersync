//! Structure-aware fuzz target for HTTP/1 client URL parsing.
//!
//! Targets [`ParsedUrl::parse`] in `src/http/h1/http_client.rs`.
//! The harness combines raw URL inputs with structured generation so libFuzzer
//! can mutate realistic authorities, ports, and path/query boundaries.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::http::h1::http_client::Scheme;
use asupersync::http::h1::{ClientError, ParsedUrl};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;
const MAX_COMPONENT_LEN: usize = 256;

#[derive(Arbitrary, Debug, Clone)]
enum SchemeStrategy {
    Http,
    Https,
    Unsupported(String),
    Missing,
}

#[derive(Arbitrary, Debug, Clone)]
enum AuthorityStrategy {
    Hostname {
        label: String,
        domain: String,
        port: Option<u16>,
    },
    Ipv4 {
        octets: [u8; 4],
        port: Option<u16>,
    },
    BracketedIpv6 {
        segments: [u16; 8],
        port: Option<u16>,
        close_bracket: bool,
    },
    UnbracketedIpv6 {
        segments: [u16; 8],
    },
    Empty,
    UserInfo {
        username: String,
        password: String,
        host: String,
    },
    InvalidPort {
        host: String,
        port_text: String,
    },
    Whitespace {
        host: String,
        whitespace: String,
    },
    Garbage(String),
}

#[derive(Arbitrary, Debug, Clone)]
enum TailStrategy {
    Root,
    Path {
        path: String,
    },
    Query {
        query: String,
    },
    Fragment {
        fragment: String,
    },
    PathQueryFragment {
        path: String,
        query: String,
        fragment: String,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct StructuredUrlInput {
    scheme: SchemeStrategy,
    authority: AuthorityStrategy,
    tail: TailStrategy,
    append_suffix: String,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(input) = Unstructured::new(data).arbitrary::<StructuredUrlInput>() {
        let url = build_url(&input);
        exercise_url(&url);
    }

    if let Ok(url) = std::str::from_utf8(data) {
        exercise_url(url);
    } else {
        let lossy = String::from_utf8_lossy(data);
        if lossy.len() <= MAX_INPUT_LEN {
            exercise_url(&lossy);
        }
    }
});

fn exercise_url(url: &str) {
    let result = ParsedUrl::parse(url);
    let (scheme, rest) = match split_scheme(url) {
        Some(parts) => parts,
        None => {
            assert!(matches!(result, Err(ClientError::InvalidUrl(_))));
            return;
        }
    };

    let authority_end = rest
        .find(|c| matches!(c, '/' | '?' | '#'))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let suffix = &rest[authority_end..];

    if authority.contains('@') && !authority.starts_with('[') {
        assert!(matches!(result, Err(ClientError::InvalidUrl(_))));
        return;
    }
    if contains_ctl_or_whitespace(authority) {
        assert!(matches!(result, Err(ClientError::InvalidUrl(_))));
        return;
    }

    match result {
        Ok(parsed) => {
            assert_eq!(parsed.scheme, scheme, "scheme must track the URL prefix");
            assert!(
                !parsed.host.is_empty(),
                "successful parses must never produce an empty host"
            );
            assert!(
                !contains_ctl_or_whitespace(&parsed.host),
                "successful parses must not preserve authority whitespace"
            );

            if authority.starts_with('[') {
                assert!(
                    parsed.host.starts_with('['),
                    "bracketed IPv6 hosts must retain brackets"
                );
                assert!(
                    parsed.host.ends_with(']'),
                    "bracketed IPv6 hosts must retain the closing bracket"
                );
            }

            let explicit_port = expected_explicit_port(authority);
            let expected_port = explicit_port.unwrap_or(match scheme {
                Scheme::Http => 80,
                Scheme::Https => 443,
            });
            assert_eq!(parsed.port, expected_port, "port selection drifted");

            let expected_path = if suffix.is_empty() { "/" } else { suffix };
            assert_eq!(
                parsed.path, expected_path,
                "path/query preservation drifted"
            );

            if let Some(explicit_host) = expected_host(authority) {
                assert_eq!(
                    parsed.host, explicit_host,
                    "authority host extraction drifted"
                );
            }
        }
        Err(ClientError::InvalidUrl(_)) => {
            if authority.is_empty() {
                return;
            }

            if authority.starts_with('[') {
                assert!(
                    !authority.contains(']')
                        || authority[authority.find(']').unwrap() + 1..].starts_with(':')
                        || authority.ends_with(']'),
                    "bracketed IPv6 failures should come from malformed bracket or port syntax"
                );
                return;
            }

            if let Some(port_text) = trailing_port_text(authority) {
                if !port_text.is_empty() && port_text.parse::<u16>().is_err() {
                    return;
                }
            }
        }
        Err(other) => panic!("unexpected non-URL parser error for {url:?}: {other:?}"),
    }
}

fn build_url(input: &StructuredUrlInput) -> String {
    let mut out = String::new();

    match &input.scheme {
        SchemeStrategy::Http => out.push_str("http://"),
        SchemeStrategy::Https => out.push_str("https://"),
        SchemeStrategy::Unsupported(other) => {
            out.push_str(&sanitize_component(other));
            out.push_str("://");
        }
        SchemeStrategy::Missing => {}
    }

    out.push_str(&build_authority(&input.authority));
    out.push_str(&build_tail(&input.tail));
    out.push_str(&sanitize_component(&input.append_suffix));
    out
}

fn build_authority(authority: &AuthorityStrategy) -> String {
    match authority {
        AuthorityStrategy::Hostname {
            label,
            domain,
            port,
        } => {
            let host = format!(
                "{}.{}",
                sanitize_label(label, "example"),
                sanitize_label(domain, "test")
            );
            match port {
                Some(port) => format!("{host}:{port}"),
                None => host,
            }
        }
        AuthorityStrategy::Ipv4 { octets, port } => {
            let host = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
            match port {
                Some(port) => format!("{host}:{port}"),
                None => host,
            }
        }
        AuthorityStrategy::BracketedIpv6 {
            segments,
            port,
            close_bracket,
        } => {
            let base = format!(
                "[{}{}",
                render_ipv6(segments),
                if *close_bracket { "]" } else { "" }
            );
            match (*close_bracket, *port) {
                (true, Some(port)) => format!("{base}:{port}"),
                _ => base,
            }
        }
        AuthorityStrategy::UnbracketedIpv6 { segments } => render_ipv6(segments),
        AuthorityStrategy::Empty => String::new(),
        AuthorityStrategy::UserInfo {
            username,
            password,
            host,
        } => format!(
            "{}:{}@{}",
            sanitize_component(username),
            sanitize_component(password),
            sanitize_label(host, "proxy")
        ),
        AuthorityStrategy::InvalidPort { host, port_text } => {
            format!(
                "{}:{}",
                sanitize_label(host, "example"),
                sanitize_component(port_text)
            )
        }
        AuthorityStrategy::Whitespace { host, whitespace } => {
            format!(
                "{}{}",
                sanitize_label(host, "example"),
                whitespace
                    .chars()
                    .map(|c| if c.is_whitespace() { c } else { ' ' })
                    .collect::<String>()
            )
        }
        AuthorityStrategy::Garbage(value) => sanitize_component(value),
    }
}

fn build_tail(tail: &TailStrategy) -> String {
    match tail {
        TailStrategy::Root => "/".to_string(),
        TailStrategy::Path { path } => format!("/{}", sanitize_path(path)),
        TailStrategy::Query { query } => format!("?{}", sanitize_query_like(query)),
        TailStrategy::Fragment { fragment } => format!("#{}", sanitize_query_like(fragment)),
        TailStrategy::PathQueryFragment {
            path,
            query,
            fragment,
        } => format!(
            "/{}?{}#{}",
            sanitize_path(path),
            sanitize_query_like(query),
            sanitize_query_like(fragment)
        ),
    }
}

fn split_scheme(url: &str) -> Option<(Scheme, &str)> {
    if let Some(rest) = url.strip_prefix("https://") {
        Some((Scheme::Https, rest))
    } else if let Some(rest) = url.strip_prefix("http://") {
        Some((Scheme::Http, rest))
    } else {
        None
    }
}

fn expected_host(authority: &str) -> Option<String> {
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let rest = &authority[end + 1..];
        if rest.is_empty() || rest.starts_with(':') {
            return Some(authority[..=end].to_string());
        }
        return None;
    }

    if authority.matches(':').count() > 1 {
        return Some(authority.to_string());
    }

    authority
        .rfind(':')
        .map(|idx| authority[..idx].to_string())
        .or_else(|| Some(authority.to_string()))
}

fn expected_explicit_port(authority: &str) -> Option<u16> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return authority[end + 1..].strip_prefix(':')?.parse().ok();
    }

    if authority.matches(':').count() > 1 {
        return None;
    }

    let (_, port) = authority.rsplit_once(':')?;
    port.parse().ok()
}

fn trailing_port_text(authority: &str) -> Option<&str> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return authority[end + 1..].strip_prefix(':');
    }
    if authority.matches(':').count() > 1 {
        return None;
    }
    authority.rsplit_once(':').map(|(_, port)| port)
}

fn render_ipv6(segments: &[u16; 8]) -> String {
    segments
        .iter()
        .map(|segment| format!("{segment:x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn sanitize_label(input: &str, fallback: &str) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(MAX_COMPONENT_LEN)
        .collect();
    if filtered.is_empty() {
        fallback.to_string()
    } else {
        filtered
    }
}

fn sanitize_path(input: &str) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| !c.is_ascii_control() && *c != '?' && *c != '#')
        .take(MAX_COMPONENT_LEN)
        .collect();
    if filtered.is_empty() {
        "path".to_string()
    } else {
        filtered
    }
}

fn sanitize_query_like(input: &str) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| !c.is_ascii_control() && *c != '#' && *c != '\r' && *c != '\n')
        .take(MAX_COMPONENT_LEN)
        .collect();
    if filtered.is_empty() {
        "k=v".to_string()
    } else {
        filtered
    }
}

fn sanitize_component(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_ascii_control())
        .take(MAX_COMPONENT_LEN)
        .collect()
}

fn contains_ctl_or_whitespace(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_control() || c.is_whitespace())
}
