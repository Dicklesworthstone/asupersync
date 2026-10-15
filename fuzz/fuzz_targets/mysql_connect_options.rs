#![no_main]

use arbitrary::Arbitrary;
use asupersync::database::mysql::{MySqlConnectOptions, SslMode};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;

const MAX_RAW_URL_BYTES: usize = 256;
const MAX_COMPONENT_CHARS: usize = 32;

type ParseOutcome = Result<MySqlConnectOptions, String>;
type PanicPayload = Box<dyn std::any::Any + Send>;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Raw(Vec<u8>),
    Structured(StructuredUrl),
}

#[derive(Arbitrary, Debug)]
struct StructuredUrl {
    user: Vec<u8>,
    password: Vec<u8>,
    host_seed: Vec<u8>,
    database: Vec<u8>,
    charset: Vec<u8>,
    port: u16,
    connect_timeout_secs: u16,
    auth_mode: AuthMode,
    host_mode: HostMode,
    query_mode: QueryMode,
    ssl_mode: StructuredSslMode,
    include_unknown_param: bool,
    include_database: bool,
    mutation: UrlMutation,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    None,
    UserOnly,
    UserPassword,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum HostMode {
    Domain,
    Ipv4,
    Ipv6,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum QueryMode {
    None,
    SslOnly,
    TimeoutOnly,
    CharsetOnly,
    All,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum StructuredSslMode {
    Disabled,
    Preferred,
    Required,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum UrlMutation {
    Valid,
    BadScheme,
    MissingHost,
    BadPort,
    InvalidSslMode,
    InvalidTimeout,
    UnclosedIpv6,
}

#[derive(Debug)]
struct UrlExpectation {
    expected: Option<ExpectedOptions>,
    must_reject: bool,
}

#[derive(Debug)]
struct ExpectedOptions {
    host: String,
    port: u16,
    database: Option<String>,
    user: String,
    password: Option<String>,
    ssl_mode: SslMode,
    connect_timeout: Option<Duration>,
    requested_charset: Option<String>,
}

impl StructuredUrl {
    fn materialize(&self) -> (String, UrlExpectation) {
        let encoded_user = encode_component(&sanitize_generic(&self.user, "user"));
        let encoded_password = encode_component(&sanitize_generic(&self.password, "password"));
        let host = materialize_host(&self.host_seed, self.host_mode);
        let database = self
            .include_database
            .then(|| sanitize_database(&self.database, "db"));
        let charset = matches!(self.query_mode, QueryMode::CharsetOnly | QueryMode::All)
            .then(|| sanitize_generic(&self.charset, "utf8mb4"));
        let expected_ssl_mode = self.ssl_mode.as_runtime();
        let connect_timeout = matches!(self.query_mode, QueryMode::TimeoutOnly | QueryMode::All)
            .then_some(Duration::from_secs(u64::from(self.connect_timeout_secs)));

        let auth = match self.auth_mode {
            AuthMode::None => String::new(),
            AuthMode::UserOnly => format!("{encoded_user}@"),
            AuthMode::UserPassword => format!("{encoded_user}:{encoded_password}@"),
        };

        let host_port = match (self.mutation, self.host_mode) {
            (UrlMutation::MissingHost, _) => ":3306".to_owned(),
            (UrlMutation::BadPort, HostMode::Ipv6) => format!("[{host}]:not-a-port"),
            (UrlMutation::BadPort, _) => format!("{host}:not-a-port"),
            (UrlMutation::UnclosedIpv6, HostMode::Ipv6) => format!("[{host}:{}", self.port),
            (UrlMutation::UnclosedIpv6, _) => "[::1:3306".to_owned(),
            (_, HostMode::Ipv6) => format!("[{host}]:{}", self.port),
            _ => format!("{host}:{}", self.port),
        };

        let mut url = String::from("mysql://");
        if self.mutation == UrlMutation::BadScheme {
            url = String::from("postgres://");
        }
        url.push_str(&auth);
        url.push_str(&host_port);
        if let Some(database) = &database {
            url.push('/');
            url.push_str(&encode_component(database));
        }

        let mut params = Vec::new();
        match self.query_mode {
            QueryMode::None => {}
            QueryMode::SslOnly | QueryMode::All => {
                let value = if self.mutation == UrlMutation::InvalidSslMode {
                    "bogus".to_owned()
                } else {
                    self.ssl_mode.as_query_value().to_owned()
                };
                params.push(("ssl%2Dmode".to_owned(), value));
            }
            _ => {}
        }
        match self.query_mode {
            QueryMode::TimeoutOnly | QueryMode::All => {
                let value = if self.mutation == UrlMutation::InvalidTimeout {
                    "not-a-number".to_owned()
                } else {
                    self.connect_timeout_secs.to_string()
                };
                params.push(("connect%5Ftimeout".to_owned(), value));
            }
            _ => {}
        }
        match self.query_mode {
            QueryMode::CharsetOnly | QueryMode::All => {
                let charset = charset.clone().unwrap_or_else(|| "utf8mb4".to_owned());
                params.push(("charset".to_owned(), encode_component(&charset)));
            }
            _ => {}
        }
        if self.include_unknown_param {
            params.push(("unknown".to_owned(), "value".to_owned()));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(
                &params
                    .into_iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }

        let must_reject = self.mutation != UrlMutation::Valid;
        let expected = (!must_reject).then_some(ExpectedOptions {
            host,
            port: self.port,
            database,
            user: match self.auth_mode {
                AuthMode::None => "root".to_owned(),
                _ => sanitize_generic(&self.user, "user"),
            },
            password: matches!(self.auth_mode, AuthMode::UserPassword)
                .then(|| sanitize_generic(&self.password, "password")),
            ssl_mode: expected_ssl_mode,
            connect_timeout,
            requested_charset: charset,
        });
        (
            url,
            UrlExpectation {
                expected,
                must_reject,
            },
        )
    }
}

impl StructuredSslMode {
    fn as_runtime(self) -> SslMode {
        match self {
            Self::Disabled => SslMode::Disabled,
            Self::Preferred => SslMode::Preferred,
            Self::Required => SslMode::Required,
        }
    }

    fn as_query_value(self) -> &'static str {
        match self {
            Self::Disabled => "DiSaBlEd",
            Self::Preferred => "PrEfErReD",
            Self::Required => "ReQuIrEd",
        }
    }
}

fn materialize_host(seed: &[u8], mode: HostMode) -> String {
    match mode {
        HostMode::Domain => sanitize_host(seed, "localhost"),
        HostMode::Ipv4 => {
            let bytes = [0, 1, 2, 3].map(|index| seed.get(index).copied().unwrap_or(index as u8));
            format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
        }
        HostMode::Ipv6 => {
            let mut groups = Vec::with_capacity(8);
            for index in 0..8 {
                let hi = seed.get(index * 2).copied().unwrap_or(index as u8);
                let lo = seed
                    .get(index * 2 + 1)
                    .copied()
                    .unwrap_or((index * 3) as u8);
                groups.push(format!("{:x}", u16::from_be_bytes([hi, lo])));
            }
            groups.join(":")
        }
    }
}

fn sanitize_generic(bytes: &[u8], fallback: &str) -> String {
    let text: String = String::from_utf8_lossy(bytes)
        .chars()
        .filter(|ch| !ch.is_control())
        .filter(|ch| !matches!(ch, '@' | ':' | '/' | '?' | '&' | '#'))
        .take(MAX_COMPONENT_CHARS)
        .collect();
    if text.is_empty() {
        fallback.to_owned()
    } else {
        text
    }
}

fn sanitize_database(bytes: &[u8], fallback: &str) -> String {
    sanitize_generic(bytes, fallback).replace('%', "pct")
}

fn sanitize_host(bytes: &[u8], fallback: &str) -> String {
    let text: String = String::from_utf8_lossy(bytes)
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.') {
                ch
            } else {
                '-'
            }
        })
        .take(MAX_COMPONENT_CHARS)
        .collect();
    if text.trim_matches('-').is_empty() {
        fallback.to_owned()
    } else {
        text
    }
}

fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex_upper(byte >> 4));
            out.push(hex_upper(byte & 0x0F));
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'A' + nibble - 10),
        _ => unreachable!("nibble out of range"),
    }
}

fn parse_no_panic(url: &str) -> Result<ParseOutcome, PanicPayload> {
    catch_unwind(AssertUnwindSafe(|| {
        MySqlConnectOptions::parse(url).map_err(|err| err.to_string())
    }))
}

fn exercise_raw(url: &str) {
    let result = parse_no_panic(url);
    assert!(
        result.is_ok(),
        "MySqlConnectOptions::parse panicked on raw input {url:?}"
    );
}

fn exercise_structured(url: &str, expectation: UrlExpectation) {
    let result = parse_no_panic(url);
    assert!(
        result.is_ok(),
        "MySqlConnectOptions::parse panicked on structured input {url:?}"
    );
    let result = result.expect("panic checked above");

    if expectation.must_reject {
        assert!(
            result.is_err(),
            "structured-invalid MySQL URL unexpectedly parsed: {url:?} -> {result:?}"
        );
        return;
    }

    let options = result.expect("structured-valid MySQL URL must parse");
    let expected = expectation.expected.expect("valid URL expectation");
    assert_eq!(options.host, expected.host);
    assert_eq!(options.port, expected.port);
    assert_eq!(options.database, expected.database);
    assert_eq!(options.user, expected.user);
    assert_eq!(
        options.password.as_ref().map(|password| password.as_str()),
        expected.password.as_deref()
    );
    assert_eq!(options.ssl_mode, expected.ssl_mode);
    assert_eq!(options.connect_timeout, expected.connect_timeout);
    assert_eq!(options.requested_charset, expected.requested_charset);
    assert!(
        !options.host.is_empty(),
        "parsed host must remain non-empty"
    );

    if let Some(password) = expected.password {
        let debug = format!("{options:?}");
        assert!(
            !debug.contains(&password),
            "Debug output must not leak plaintext password"
        );
        assert!(
            debug.contains("[REDACTED]"),
            "Debug output must mark password as redacted"
        );
    }
}

fuzz_target!(|input: FuzzInput| {
    match input {
        FuzzInput::Raw(bytes) => {
            if bytes.len() > MAX_RAW_URL_BYTES {
                return;
            }
            let url = String::from_utf8_lossy(&bytes).into_owned();
            exercise_raw(&url);
        }
        FuzzInput::Structured(input) => {
            let (url, expectation) = input.materialize();
            exercise_structured(&url, expectation);
        }
    }
});
