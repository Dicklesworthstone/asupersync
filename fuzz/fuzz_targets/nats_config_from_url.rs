#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::nats::NatsConfig;
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

const MAX_RAW_URL_BYTES: usize = 512;
const MAX_COMPONENT_CHARS: usize = 32;

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

type ParseOutcome = Result<NatsConfig, String>;
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
    token: Vec<u8>,
    host_seed: Vec<u8>,
    port: u16,
    auth_mode: AuthMode,
    host_mode: HostMode,
    mutation: UrlMutation,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    None,
    UserPassword,
    Token,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum HostMode {
    Domain,
    Ipv4,
    Ipv6,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum UrlMutation {
    Valid,
    BadScheme,
    EmptyHostWithPort,
    BadPort,
    UnclosedIpv6,
    ExtraIpv6Tail,
}

#[derive(Debug)]
struct UrlExpectation {
    expected: Option<ExpectedConfig>,
    must_reject: bool,
}

#[derive(Debug)]
struct ExpectedConfig {
    host: String,
    port: u16,
    user: Option<String>,
    password: Option<String>,
    token: Option<String>,
}

impl StructuredUrl {
    fn materialize(&self) -> (String, UrlExpectation) {
        let user = sanitize_secret(&self.user, "user");
        let password = sanitize_secret(&self.password, "password");
        let token = sanitize_secret(&self.token, "token");
        let (host_for_url, expected_host) = materialize_host(&self.host_seed, self.host_mode);

        let auth = match self.auth_mode {
            AuthMode::None => String::new(),
            AuthMode::UserPassword => format!("{user}:{password}@"),
            AuthMode::Token => format!("{token}@"),
        };

        let host_port = match (self.mutation, self.host_mode) {
            (UrlMutation::EmptyHostWithPort, _) => format!(":{}", self.port),
            (UrlMutation::BadPort, HostMode::Ipv6) => format!("[{host_for_url}]:not-a-port"),
            (UrlMutation::BadPort, _) => format!("{host_for_url}:not-a-port"),
            (UrlMutation::UnclosedIpv6, HostMode::Ipv6) => format!("[{host_for_url}:{}", self.port),
            (UrlMutation::UnclosedIpv6, _) => format!("[{host_for_url}:{}", self.port),
            (UrlMutation::ExtraIpv6Tail, HostMode::Ipv6) => {
                format!("[{host_for_url}]tail:{}", self.port)
            }
            (UrlMutation::ExtraIpv6Tail, _) => format!("[{host_for_url}]tail:{}", self.port),
            (_, HostMode::Ipv6) => format!("[{host_for_url}]:{}", self.port),
            _ => format!("{host_for_url}:{}", self.port),
        };

        let scheme = if self.mutation == UrlMutation::BadScheme {
            "http://"
        } else {
            "nats://"
        };
        let url = format!("{scheme}{auth}{host_port}");
        let must_reject = self.mutation != UrlMutation::Valid;
        let expected = (!must_reject).then_some(ExpectedConfig {
            host: expected_host,
            port: self.port,
            user: matches!(self.auth_mode, AuthMode::UserPassword).then_some(user),
            password: matches!(self.auth_mode, AuthMode::UserPassword).then_some(password),
            token: matches!(self.auth_mode, AuthMode::Token).then_some(token),
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

fn materialize_host(seed: &[u8], mode: HostMode) -> (String, String) {
    match mode {
        HostMode::Domain => {
            let host = sanitize_host(seed, "localhost");
            (host.clone(), host)
        }
        HostMode::Ipv4 => {
            let bytes = [0, 1, 2, 3].map(|index| seed.get(index).copied().unwrap_or(index as u8));
            let host = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
            (host.clone(), host)
        }
        HostMode::Ipv6 => {
            let mut groups = Vec::with_capacity(8);
            for index in 0..8 {
                let hi = seed.get(index * 2).copied().unwrap_or(index as u8);
                let lo = seed
                    .get(index * 2 + 1)
                    .copied()
                    .unwrap_or((index * 11) as u8);
                groups.push(format!("{:x}", u16::from_be_bytes([hi, lo])));
            }
            let host = groups.join(":");
            (host.clone(), format!("[{host}]"))
        }
    }
}

fn sanitize_secret(bytes: &[u8], prefix: &str) -> String {
    format!("{prefix}_{}", sanitize_token(bytes, "value"))
}

fn sanitize_token(bytes: &[u8], fallback: &str) -> String {
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

fn parse_no_panic(url: &str) -> Result<ParseOutcome, PanicPayload> {
    catch_unwind(AssertUnwindSafe(|| {
        NatsConfig::from_url(url).map_err(|err| err.to_string())
    }))
}

fn exercise_raw(url: &str) {
    match parse_no_panic(url) {
        Ok(result) => observe_raw_parse_outcome(url, result),
        Err(_) => panic!("NatsConfig::from_url panicked on raw input {url:?}"),
    }
}

fn assert_url_rejection(url: &str, expected: &str) {
    let result = parse_no_panic(url).expect("fixed NATS URL canary should not panic");
    let error = result.expect_err("fixed NATS URL canary should be rejected");

    assert_eq!(error, expected, "NATS URL diagnostic drift for {url:?}",);
    assert!(
        !error.trim().is_empty(),
        "NATS URL rejection should expose a diagnostic for {url:?}"
    );
}

fn assert_fixed_url_error_canaries() {
    assert_url_rejection(
        "http://localhost:4222",
        "Invalid NATS URL: http://localhost:4222",
    );
    assert_url_rejection("nats://:4222", "Invalid NATS URL: host must not be empty");
    assert_url_rejection(
        "nats://localhost:not-a-port",
        "Invalid NATS URL: invalid port: not-a-port",
    );
    assert_url_rejection("nats://[::1", "Invalid NATS URL: invalid IPv6 host");
    assert_url_rejection(
        "nats://[::1]tail:4222",
        "Invalid NATS URL: invalid host/port: [::1]tail:4222",
    );
}

fn observe_raw_parse_outcome(url: &str, result: ParseOutcome) {
    match result {
        Ok(config) => {
            assert!(
                !config.host.is_empty(),
                "raw NATS URL parsed with an empty host: {url:?}"
            );
            assert!(
                config.host.len() <= MAX_RAW_URL_BYTES,
                "raw NATS URL parsed into an unexpectedly large host: {} bytes",
                config.host.len()
            );
        }
        Err(message) => {
            assert!(
                !message.trim().is_empty(),
                "raw NATS URL rejection should expose a diagnostic for {url:?}"
            );
        }
    }
}

fn exercise_structured(url: &str, expectation: UrlExpectation) {
    let result = parse_no_panic(url);
    assert!(
        result.is_ok(),
        "NatsConfig::from_url panicked on structured input {url:?}"
    );
    let result = result.expect("panic checked above");

    if expectation.must_reject {
        assert!(
            result.is_err(),
            "structured-invalid NATS URL unexpectedly parsed: {url:?} -> {result:?}"
        );
        return;
    }

    let config = result.expect("structured-valid NATS URL must parse");
    let expected = expectation.expected.expect("valid URL expectation");
    assert_eq!(config.host, expected.host);
    assert_eq!(config.port, expected.port);
    assert_eq!(config.user, expected.user);
    assert_eq!(config.password, expected.password);
    assert_eq!(config.token, expected.token);
    assert!(!config.host.is_empty(), "parsed host must remain non-empty");

    let debug = format!("{config:?}");
    if expected.user.is_some() || expected.password.is_some() || expected.token.is_some() {
        assert!(
            debug.contains("<redacted>"),
            "Debug output must mark credentials as redacted"
        );
    }
    for secret in [
        expected.user.as_deref(),
        expected.password.as_deref(),
        expected.token.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if secret != config.host {
            assert!(
                !debug.contains(secret),
                "Debug output must not leak parsed credential {secret:?}"
            );
        }
    }
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
