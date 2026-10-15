#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::nats::{
    fuzz_deterministic_nats_user_seed, fuzz_load_nats_user_nkey, fuzz_parse_nats_creds,
    fuzz_parse_nats_jwt_claims,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value, json};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

const MAX_TEXT_CHARS: usize = 64;
const MAX_RAW_BYTES: usize = 256;
const NATS_CREDS_JWT_BEGIN: &str = "-----BEGIN NATS USER JWT-----";
const NATS_CREDS_JWT_END: &str = "------END NATS USER JWT------";
const NATS_CREDS_SEED_BEGIN: &str = "-----BEGIN USER NKEY SEED-----";
const NATS_CREDS_SEED_END: &str = "------END USER NKEY SEED------";

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

type ClaimsTuple = (String, Option<String>, Option<String>, Option<i64>);
type JwtParseResult = Result<ClaimsTuple, String>;
type CredsParseResult = Result<(String, String), String>;
type SeedParseResult = Result<String, String>;
type PanicPayload = Box<dyn std::any::Any + Send>;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    RawJwt(Vec<u8>),
    StructuredJwt(StructuredJwtInput),
    RawCreds(Vec<u8>),
    StructuredCreds(StructuredCredsInput),
    Seed(SeedInput),
}

#[derive(Arbitrary, Debug)]
struct StructuredJwtInput {
    subject: Vec<u8>,
    issuer: Vec<u8>,
    name: Vec<u8>,
    exp: Option<i64>,
    include_issuer: bool,
    include_name: bool,
    mutation: JwtMutation,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum JwtMutation {
    Valid,
    MissingSubject,
    EmptySubject,
    NonObjectHeader,
    NonObjectPayload,
    InvalidHeaderBase64,
    InvalidPayloadJson,
    WrongSegmentCount,
    EmptySignature,
}

#[derive(Arbitrary, Debug)]
struct StructuredCredsInput {
    seed_byte: u8,
    issuer: Vec<u8>,
    name: Vec<u8>,
    exp: Option<i64>,
    wrap_width: u8,
    blank_lines: bool,
    mutation: CredsMutation,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum CredsMutation {
    Valid,
    MissingJwtBegin,
    MissingJwtEnd,
    MissingSeedBegin,
    MissingSeedEnd,
    EmptyJwtBlock,
    EmptySeedBlock,
}

#[derive(Arbitrary, Debug)]
struct SeedInput {
    raw: Vec<u8>,
    seed_byte: u8,
    mutation: SeedMutation,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum SeedMutation {
    ValidDeterministic,
    TruncatedDeterministic,
    InvalidChar,
    RawLossy,
}

#[derive(Debug)]
struct JwtExpectation {
    claims: Option<ExpectedClaims>,
    must_reject: bool,
}

#[derive(Debug)]
struct CredsExpectation {
    parsed_jwt: Option<String>,
    parsed_seed: Option<String>,
    claims: Option<ExpectedClaims>,
    public_key: Option<String>,
    must_reject: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedClaims {
    subject: String,
    issuer: Option<String>,
    name: Option<String>,
    expires_at: Option<i64>,
}

impl StructuredJwtInput {
    fn materialize(&self) -> (String, JwtExpectation) {
        let subject = sanitize_text(&self.subject, "subject");
        let issuer = self
            .include_issuer
            .then(|| sanitize_text(&self.issuer, "issuer"));
        let name = self.include_name.then(|| sanitize_text(&self.name, "name"));
        let claims = ExpectedClaims {
            subject: subject.clone(),
            issuer: issuer.clone(),
            name: name.clone(),
            expires_at: self.exp,
        };

        let header_segment = match self.mutation {
            JwtMutation::InvalidHeaderBase64 => "*".repeat(3),
            JwtMutation::NonObjectHeader => encode_json(&json!(["not-an-object"])),
            _ => encode_json(&json!({"alg":"ed25519-nkey","typ":"JWT"})),
        };

        let payload_segment = match self.mutation {
            JwtMutation::InvalidPayloadJson => URL_SAFE_NO_PAD.encode(b"{"),
            JwtMutation::NonObjectPayload => encode_json(&json!(["not-an-object"])),
            _ => {
                let mut payload = Map::new();
                if self.mutation != JwtMutation::MissingSubject {
                    let sub = if self.mutation == JwtMutation::EmptySubject {
                        String::new()
                    } else {
                        subject
                    };
                    payload.insert("sub".to_owned(), Value::String(sub));
                }
                if let Some(issuer) = issuer {
                    payload.insert("iss".to_owned(), Value::String(issuer));
                }
                if let Some(name) = name {
                    payload.insert("name".to_owned(), Value::String(name));
                }
                if let Some(expires_at) = self.exp {
                    payload.insert("exp".to_owned(), Value::from(expires_at));
                }
                encode_json(&Value::Object(payload))
            }
        };

        let signature = if self.mutation == JwtMutation::EmptySignature {
            String::new()
        } else {
            URL_SAFE_NO_PAD.encode(b"sig")
        };
        let mut jwt = format!("{header_segment}.{payload_segment}.{signature}");
        if self.mutation == JwtMutation::WrongSegmentCount {
            jwt.push_str(".extra");
        }

        let must_reject = self.mutation != JwtMutation::Valid;
        let claims = (!must_reject).then_some(claims);
        (
            jwt,
            JwtExpectation {
                claims,
                must_reject,
            },
        )
    }
}

impl StructuredCredsInput {
    fn materialize(&self) -> (String, CredsExpectation) {
        let seed = fuzz_deterministic_nats_user_seed(self.seed_byte);
        let public_key =
            fuzz_load_nats_user_nkey(&seed).expect("deterministic user seed must always load");
        let claims = ExpectedClaims {
            subject: public_key.clone(),
            issuer: Some(sanitize_text(&self.issuer, "issuer")),
            name: Some(sanitize_text(&self.name, "name")),
            expires_at: self.exp,
        };
        let jwt = build_valid_jwt(&claims);

        let jwt_begin = if self.mutation == CredsMutation::MissingJwtBegin {
            "-----BEGIN JWT-----"
        } else {
            NATS_CREDS_JWT_BEGIN
        };
        let jwt_end = if self.mutation == CredsMutation::MissingJwtEnd {
            "------END JWT------"
        } else {
            NATS_CREDS_JWT_END
        };
        let seed_begin = if self.mutation == CredsMutation::MissingSeedBegin {
            "-----BEGIN NKEY SEED-----"
        } else {
            NATS_CREDS_SEED_BEGIN
        };
        let seed_end = if self.mutation == CredsMutation::MissingSeedEnd {
            "------END NKEY SEED------"
        } else {
            NATS_CREDS_SEED_END
        };

        let jwt_body = if self.mutation == CredsMutation::EmptyJwtBlock {
            String::new()
        } else {
            wrap_ascii_lines(&jwt, self.wrap_width, self.blank_lines)
        };
        let seed_body = if self.mutation == CredsMutation::EmptySeedBlock {
            String::new()
        } else {
            wrap_ascii_lines(&seed, self.wrap_width.wrapping_add(1), self.blank_lines)
        };

        let creds =
            format!("{jwt_begin}\n{jwt_body}\n{jwt_end}\n{seed_begin}\n{seed_body}\n{seed_end}\n");

        let must_reject = self.mutation != CredsMutation::Valid;
        (
            creds,
            CredsExpectation {
                parsed_jwt: (!must_reject).then_some(jwt),
                parsed_seed: (!must_reject).then_some(seed),
                claims: (!must_reject).then_some(claims),
                public_key: (!must_reject).then_some(public_key),
                must_reject,
            },
        )
    }
}

impl SeedInput {
    fn materialize(&self) -> (String, bool) {
        let valid_seed = fuzz_deterministic_nats_user_seed(self.seed_byte);
        match self.mutation {
            SeedMutation::ValidDeterministic => (valid_seed, true),
            SeedMutation::TruncatedDeterministic => {
                let keep = valid_seed.len().saturating_sub(1).max(1);
                (valid_seed[..keep].to_owned(), false)
            }
            SeedMutation::InvalidChar => {
                let mut invalid = valid_seed;
                invalid.replace_range(..1, "0");
                (invalid, false)
            }
            SeedMutation::RawLossy => (lossy_text(&self.raw), false),
        }
    }
}

fn sanitize_text(bytes: &[u8], fallback: &str) -> String {
    let text: String = lossy_text(bytes)
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_TEXT_CHARS)
        .collect();
    if text.is_empty() {
        fallback.to_owned()
    } else {
        text
    }
}

fn lossy_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_RAW_BYTES)]).into_owned()
}

fn encode_json(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("JSON encoding"))
}

fn build_valid_jwt(claims: &ExpectedClaims) -> String {
    let mut payload = Map::new();
    payload.insert("sub".to_owned(), Value::String(claims.subject.clone()));
    if let Some(issuer) = &claims.issuer {
        payload.insert("iss".to_owned(), Value::String(issuer.clone()));
    }
    if let Some(name) = &claims.name {
        payload.insert("name".to_owned(), Value::String(name.clone()));
    }
    if let Some(expires_at) = claims.expires_at {
        payload.insert("exp".to_owned(), Value::from(expires_at));
    }

    format!(
        "{}.{}.{}",
        encode_json(&json!({"alg":"ed25519-nkey","typ":"JWT"})),
        encode_json(&Value::Object(payload)),
        URL_SAFE_NO_PAD.encode(b"sig")
    )
}

fn assert_jwt_rejection(jwt: &str, expected: &str) {
    let error =
        fuzz_parse_nats_jwt_claims(jwt).expect_err("fixed NATS JWT canary should be rejected");
    assert_eq!(error, expected, "NATS JWT diagnostic drift for {jwt:?}");
    assert!(
        !error.trim().is_empty(),
        "NATS JWT rejection should expose a diagnostic"
    );
    assert!(
        error.len() <= 512,
        "NATS JWT rejection diagnostic should stay bounded: {} bytes",
        error.len()
    );
}

fn assert_creds_rejection(creds: &str, expected: &str) {
    let error =
        fuzz_parse_nats_creds(creds).expect_err("fixed NATS creds canary should be rejected");
    assert_eq!(error, expected, "NATS creds diagnostic drift for {creds:?}",);
    assert!(
        !error.trim().is_empty(),
        "NATS creds rejection should expose a diagnostic"
    );
    assert!(
        error.len() <= 512,
        "NATS creds rejection diagnostic should stay bounded: {} bytes",
        error.len()
    );
}

fn assert_fixed_nats_creds_jwt_error_canaries() {
    let header = encode_json(&json!({"alg":"ed25519-nkey","typ":"JWT"}));
    let payload = encode_json(&json!({"sub":"UDXEXAMPLE"}));
    let signature = URL_SAFE_NO_PAD.encode(b"sig");

    assert_jwt_rejection(
        "header.payload",
        "NATS invalid auth configuration: JWT auth expects a compact JWT with exactly 3 non-empty segments",
    );
    assert_jwt_rejection(
        &format!(
            "{}.{payload}.{signature}",
            encode_json(&json!(["not-an-object"]))
        ),
        "NATS invalid auth configuration: JWT header must decode to a JSON object",
    );
    assert_jwt_rejection(
        &format!(
            "{header}.{}.{signature}",
            encode_json(&json!(["not-an-object"]))
        ),
        "NATS invalid auth configuration: JWT payload must decode to a JSON object",
    );
    assert_jwt_rejection(
        &format!(
            "{header}.{}.{signature}",
            encode_json(&json!({"iss":"issuer"}))
        ),
        "NATS invalid auth configuration: JWT payload must contain a non-empty string sub claim",
    );

    assert_creds_rejection(
        "",
        "NATS invalid auth configuration: credentials are missing the JWT begin marker",
    );
    assert_creds_rejection(
        &format!("{NATS_CREDS_JWT_BEGIN}\nabc\n"),
        "NATS invalid auth configuration: credentials are missing the JWT end marker",
    );
    assert_creds_rejection(
        &format!("{NATS_CREDS_JWT_BEGIN}\n{NATS_CREDS_JWT_END}\n"),
        "NATS invalid auth configuration: credentials JWT block is empty",
    );
    assert_creds_rejection(
        &format!("{NATS_CREDS_JWT_BEGIN}\nabc\n{NATS_CREDS_JWT_END}\n"),
        "NATS invalid auth configuration: credentials are missing the USER NKEY SEED begin marker",
    );
    assert_creds_rejection(
        &format!(
            "{NATS_CREDS_JWT_BEGIN}\nabc\n{NATS_CREDS_JWT_END}\n{NATS_CREDS_SEED_BEGIN}\n{NATS_CREDS_SEED_END}\n"
        ),
        "NATS invalid auth configuration: credentials USER NKEY SEED block is empty",
    );
}

// Real .creds files may wrap JWT/seed bodies over multiple lines; the parser
// trims and joins non-empty lines, so valid wrapped encodings should round-trip.
fn wrap_ascii_lines(text: &str, width_byte: u8, blank_lines: bool) -> String {
    let width = match usize::from(width_byte % 32) {
        0 => text.len(),
        width => width,
    };
    if width >= text.len() {
        return text.to_owned();
    }

    let mut lines = Vec::new();
    let mut start = 0usize;
    while start < text.len() {
        let end = (start + width).min(text.len());
        lines.push(text[start..end].to_owned());
        if blank_lines {
            lines.push(String::new());
        }
        start = end;
    }
    if blank_lines && matches!(lines.last(), Some(last) if last.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

fn no_panic_jwt(jwt: &str) -> Result<JwtParseResult, PanicPayload> {
    catch_unwind(AssertUnwindSafe(|| fuzz_parse_nats_jwt_claims(jwt)))
}

fn no_panic_creds(creds: &str) -> Result<CredsParseResult, PanicPayload> {
    catch_unwind(AssertUnwindSafe(|| fuzz_parse_nats_creds(creds)))
}

fn no_panic_seed(seed: &str) -> Result<SeedParseResult, PanicPayload> {
    catch_unwind(AssertUnwindSafe(|| fuzz_load_nats_user_nkey(seed)))
}

fn assert_jwt_no_panic(jwt: &str) {
    let result = no_panic_jwt(jwt);
    assert!(
        result.is_ok(),
        "parse_nats_jwt_claims panicked on input {jwt:?}"
    );
}

fn assert_creds_no_panic(creds: &str) {
    let result = no_panic_creds(creds);
    assert!(
        result.is_ok(),
        "parse_nats_creds panicked on input {creds:?}"
    );
}

fn assert_seed_no_panic(seed: &str) {
    let result = no_panic_seed(seed);
    assert!(result.is_ok(), "load_user_nkey panicked on input {seed:?}");
}

fn exercise_jwt(jwt: &str, expectation: JwtExpectation) {
    let result = no_panic_jwt(jwt);
    assert!(
        result.is_ok(),
        "parse_nats_jwt_claims panicked on input {jwt:?}"
    );
    let result = result.expect("panic checked above");

    if expectation.must_reject {
        assert!(
            result.is_err(),
            "structured-invalid JWT unexpectedly parsed: {jwt:?} -> {result:?}"
        );
        return;
    }

    let parsed = result.expect("structured-valid JWT must parse");
    let claims = expectation.claims.expect("valid JWT expectation");
    assert_eq!(parsed.0, claims.subject);
    assert_eq!(parsed.1, claims.issuer);
    assert_eq!(parsed.2, claims.name);
    assert_eq!(parsed.3, claims.expires_at);
}

fn exercise_creds(creds: &str, expectation: CredsExpectation) {
    let result = no_panic_creds(creds);
    assert!(
        result.is_ok(),
        "parse_nats_creds panicked on input {creds:?}"
    );
    let result = result.expect("panic checked above");

    if expectation.must_reject {
        assert!(
            result.is_err(),
            "structured-invalid creds unexpectedly parsed: {creds:?} -> {result:?}"
        );
        return;
    }

    let (parsed_jwt, parsed_seed) = result.expect("structured-valid creds must parse");
    let expected_jwt = expectation.parsed_jwt.expect("valid creds expected JWT");
    let expected_seed = expectation.parsed_seed.expect("valid creds expected seed");
    assert_eq!(parsed_jwt, expected_jwt);
    assert_eq!(parsed_seed, expected_seed);

    let claims = expectation.claims.expect("valid creds expected claims");
    exercise_jwt(
        &parsed_jwt,
        JwtExpectation {
            claims: Some(claims.clone()),
            must_reject: false,
        },
    );

    let seed_result = no_panic_seed(&parsed_seed);
    assert!(
        seed_result.is_ok(),
        "load_user_nkey panicked on parsed seed {parsed_seed:?}"
    );
    let public_key = seed_result
        .expect("panic checked above")
        .expect("parsed deterministic seed must load");
    assert_eq!(
        public_key,
        expectation.public_key.expect("valid creds public key")
    );
    assert_eq!(public_key, claims.subject);
}

fn exercise_seed(seed: &str, expect_success: bool) {
    let result = no_panic_seed(seed);
    assert!(result.is_ok(), "load_user_nkey panicked on input {seed:?}");
    let result = result.expect("panic checked above");
    if expect_success {
        let public_key = result.expect("deterministic seed must load");
        assert!(!public_key.is_empty());
    }
}

fuzz_target!(|input: FuzzInput| {
    FIXED_CANARIES.get_or_init(assert_fixed_nats_creds_jwt_error_canaries);

    match input {
        FuzzInput::RawJwt(bytes) => {
            let jwt = lossy_text(&bytes);
            assert_jwt_no_panic(&jwt);
        }
        FuzzInput::StructuredJwt(input) => {
            let (jwt, expectation) = input.materialize();
            exercise_jwt(&jwt, expectation);
        }
        FuzzInput::RawCreds(bytes) => {
            let creds = lossy_text(&bytes);
            assert_creds_no_panic(&creds);
        }
        FuzzInput::StructuredCreds(input) => {
            let (creds, expectation) = input.materialize();
            exercise_creds(&creds, expectation);
        }
        FuzzInput::Seed(input) => {
            let (seed, expect_success) = input.materialize();
            if expect_success {
                exercise_seed(&seed, true);
            } else {
                assert_seed_no_panic(&seed);
            }
        }
    }
});
