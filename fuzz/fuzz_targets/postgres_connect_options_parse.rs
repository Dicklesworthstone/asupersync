#![no_main]

use arbitrary::Arbitrary;
use asupersync::database::postgres::{PgConnectOptions, PgError, SslMode};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use std::time::Duration;

const MAX_RAW_URL_BYTES: usize = 512;
const MAX_COMPONENT_CHARS: usize = 32;

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

type ParseOutcome = Result<PgConnectOptions, String>;
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
    application_name: Vec<u8>,
    port: u16,
    connect_timeout_secs: u16,
    scheme: PgScheme,
    auth_mode: AuthMode,
    host_mode: HostMode,
    query_mode: QueryMode,
    ssl_mode: StructuredSslMode,
    include_unknown_param: bool,
    mutation: UrlMutation,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum PgScheme {
    Postgres,
    Postgresql,
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
    ApplicationOnly,
    All,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum StructuredSslMode {
    Disable,
    Prefer,
    Require,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum UrlMutation {
    Valid,
    BadScheme,
    MissingHost,
    MissingDatabase,
    EmptyDatabase,
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
    database: String,
    user: String,
    password: Option<String>,
    application_name: Option<String>,
    connect_timeout: Option<Duration>,
    ssl_mode: SslMode,
}

impl StructuredUrl {
    fn materialize(&self) -> (String, UrlExpectation) {
        let user = sanitize_component(&self.user, "user");
        let password = sanitize_component(&self.password, "password");
        let host = materialize_host(&self.host_seed, self.host_mode);
        let database = sanitize_component(&self.database, "db");
        let include_ssl = matches!(self.query_mode, QueryMode::SslOnly | QueryMode::All)
            || self.mutation == UrlMutation::InvalidSslMode;
        let include_timeout = matches!(self.query_mode, QueryMode::TimeoutOnly | QueryMode::All)
            || self.mutation == UrlMutation::InvalidTimeout;
        let include_application =
            matches!(self.query_mode, QueryMode::ApplicationOnly | QueryMode::All);
        let application_name =
            include_application.then(|| sanitize_component(&self.application_name, "app"));
        let connect_timeout =
            include_timeout.then_some(Duration::from_secs(u64::from(self.connect_timeout_secs)));
        let expected_ssl_mode = if include_ssl {
            self.ssl_mode.as_runtime()
        } else {
            SslMode::Prefer
        };

        let auth = match self.auth_mode {
            AuthMode::None => String::new(),
            AuthMode::UserOnly => format!("{}@", encode_component(&user)),
            AuthMode::UserPassword => {
                format!(
                    "{}:{}@",
                    encode_component(&user),
                    encode_component(&password)
                )
            }
        };

        let host_port = match (self.mutation, self.host_mode) {
            (UrlMutation::MissingHost, _) => format!(":{}", self.port),
            (UrlMutation::BadPort, HostMode::Ipv6) => format!("[{host}]:not-a-port"),
            (UrlMutation::BadPort, _) => format!("{host}:not-a-port"),
            (UrlMutation::UnclosedIpv6, HostMode::Ipv6) => format!("[{host}:{}", self.port),
            (UrlMutation::UnclosedIpv6, _) => format!("[{host}:{}", self.port),
            (_, HostMode::Ipv6) => format!("[{host}]:{}", self.port),
            _ => format!("{host}:{}", self.port),
        };

        let scheme = match (self.mutation, self.scheme) {
            (UrlMutation::BadScheme, _) => "mysql://",
            (_, PgScheme::Postgres) => "postgres://",
            (_, PgScheme::Postgresql) => "postgresql://",
        };

        let mut url = format!("{scheme}{auth}{host_port}");
        match self.mutation {
            UrlMutation::MissingDatabase => {}
            UrlMutation::EmptyDatabase => url.push('/'),
            _ => {
                url.push('/');
                url.push_str(&encode_component(&database));
            }
        }

        let mut params = Vec::new();
        if include_ssl {
            let value = if self.mutation == UrlMutation::InvalidSslMode {
                "bogus"
            } else {
                self.ssl_mode.as_query_value()
            };
            params.push(("sslmode".to_owned(), value.to_owned()));
        }
        if include_timeout {
            let value = if self.mutation == UrlMutation::InvalidTimeout {
                "not-a-number".to_owned()
            } else {
                self.connect_timeout_secs.to_string()
            };
            params.push(("connect_timeout".to_owned(), value));
        }
        if include_application {
            let value = application_name.clone().unwrap_or_else(|| "app".to_owned());
            params.push(("application_name".to_owned(), encode_component(&value)));
        }
        if self.include_unknown_param {
            params.push(("unknown".to_owned(), "ignored".to_owned()));
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
                AuthMode::None => "postgres".to_owned(),
                AuthMode::UserOnly | AuthMode::UserPassword => user,
            },
            password: matches!(self.auth_mode, AuthMode::UserPassword).then_some(password),
            application_name,
            connect_timeout,
            ssl_mode: expected_ssl_mode,
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
            Self::Disable => SslMode::Disable,
            Self::Prefer => SslMode::Prefer,
            Self::Require => SslMode::Require,
        }
    }

    fn as_query_value(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Prefer => "prefer",
            Self::Require => "require",
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
                    .unwrap_or((index * 7) as u8);
                groups.push(format!("{:x}", u16::from_be_bytes([hi, lo])));
            }
            groups.join(":")
        }
    }
}

fn sanitize_component(bytes: &[u8], fallback: &str) -> String {
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
        PgConnectOptions::parse(url).map_err(|err| err.to_string())
    }))
}

fn exercise_raw(url: &str) {
    let result = parse_no_panic(url);
    assert!(
        result.is_ok(),
        "PgConnectOptions::parse panicked on raw input {url:?}"
    );
}

fn exercise_structured(url: &str, expectation: UrlExpectation) {
    let result = parse_no_panic(url);
    assert!(
        result.is_ok(),
        "PgConnectOptions::parse panicked on structured input {url:?}"
    );
    let result = result.expect("panic checked above");

    if expectation.must_reject {
        assert!(
            result.is_err(),
            "structured-invalid PostgreSQL URL unexpectedly parsed: {url:?} -> {result:?}"
        );
        return;
    }

    let options = result.expect("structured-valid PostgreSQL URL must parse");
    let expected = expectation.expected.expect("valid URL expectation");
    assert_eq!(options.host, expected.host);
    assert_eq!(options.port, expected.port);
    assert_eq!(options.database, expected.database);
    assert_eq!(options.user, expected.user);
    assert_eq!(
        options.password.as_ref().map(|password| password.as_str()),
        expected.password.as_deref()
    );
    assert_eq!(options.application_name, expected.application_name);
    assert_eq!(options.connect_timeout, expected.connect_timeout);
    assert_eq!(options.ssl_mode, expected.ssl_mode);
    assert!(
        !options.host.is_empty(),
        "parsed host must remain non-empty"
    );
    assert!(
        !options.database.is_empty(),
        "parsed database must remain non-empty"
    );

    if expected.password.is_some() {
        let debug = format!("{options:?}");
        assert!(
            debug.contains("[REDACTED]"),
            "Debug output must mark password as redacted"
        );
    }
}

fn assert_invalid_url_rejection(url: &str, expected: &str) {
    let error =
        PgConnectOptions::parse(url).expect_err("fixed PostgreSQL URL canary should reject");

    match &error {
        PgError::InvalidUrl(message) => assert_eq!(
            message, expected,
            "PostgreSQL URL diagnostic payload changed for {url:?}"
        ),
        other => panic!("expected PostgreSQL InvalidUrl error for {url:?}, got {other:?}"),
    }

    assert_eq!(
        error.to_string(),
        format!("Invalid PostgreSQL URL: {expected}"),
        "PostgreSQL URL Display diagnostic changed for {url:?}"
    );
}

fn assert_fixed_url_error_canaries() {
    assert_invalid_url_rejection("mysql://localhost/db", "URL must start with postgres://");
    assert_invalid_url_rejection("postgres://localhost", "missing database name");
    assert_invalid_url_rejection("postgres://user@host/", "missing database name");
    assert_invalid_url_rejection("postgres://user@/db", "missing host");
    assert_invalid_url_rejection(
        "postgres://user@host:not-a-port/db",
        "invalid port: not-a-port",
    );
    assert_invalid_url_rejection(
        "postgres://user@[::1:5432/db",
        "invalid IPv6 host literal: [::1:5432",
    );
    assert_invalid_url_rejection(
        "postgres://user@[::1]oops/db",
        "invalid host/port segment: [::1]oops",
    );
    assert_invalid_url_rejection(
        "postgres://user@host/db?sslmode=magic",
        "unknown sslmode: magic",
    );
    assert_invalid_url_rejection(
        "postgres://user@host/db?connect_timeout=not-a-number",
        "invalid connect_timeout: not-a-number",
    );
}

fuzz_target!(|input: FuzzInput| {
    FIXED_CANARIES.get_or_init(assert_fixed_url_error_canaries);

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
