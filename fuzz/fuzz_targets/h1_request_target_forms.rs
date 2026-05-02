#![no_main]

//! Fuzz HTTP/1.1 request-target forms from RFC 9112 section 3.2.
//!
//! Valid forms covered:
//! - origin-form for ordinary requests, such as `GET /path HTTP/1.1`
//! - absolute-form for proxy requests, such as `GET http://host/path HTTP/1.1`
//! - authority-form for CONNECT, such as `CONNECT host:443 HTTP/1.1`
//! - asterisk-form for server-wide OPTIONS, `OPTIONS * HTTP/1.1`
//!
//! The harness also asserts that invalid method/form mixes are rejected:
//! CONNECT with origin/absolute/asterisk-form, non-CONNECT authority-form,
//! and non-OPTIONS asterisk-form.

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::{Http1Codec, HttpError, Method, Request, Version};
use libfuzzer_sys::fuzz_target;

const MAX_COMPONENT_BYTES: usize = 48;

#[derive(Arbitrary, Debug)]
struct RequestTargetCase {
    method: FuzzMethod,
    form: TargetForm,
    shape: TargetShape,
    host_seed: Vec<u8>,
    path_seed: Vec<u8>,
    query_seed: Vec<u8>,
    port_seed: u16,
    use_https: bool,
}

#[derive(Clone, Copy, Arbitrary, Debug, Eq, PartialEq)]
enum FuzzMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
}

#[derive(Clone, Copy, Arbitrary, Debug, Eq, PartialEq)]
enum TargetForm {
    Origin,
    Absolute,
    Authority,
    Asterisk,
}

#[derive(Clone, Copy, Arbitrary, Debug, Eq, PartialEq)]
enum TargetShape {
    Valid,
    Empty,
    SpaceInjected,
    ControlInjected,
    NonAsciiInjected,
    DoubleSlashOrigin,
    MissingAbsoluteAuthority,
    MissingAuthorityHost,
    MissingAuthorityPort,
}

impl FuzzMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Connect => "CONNECT",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Patch => "PATCH",
        }
    }

    fn expected(self) -> Method {
        match self {
            Self::Get => Method::Get,
            Self::Head => Method::Head,
            Self::Post => Method::Post,
            Self::Put => Method::Put,
            Self::Delete => Method::Delete,
            Self::Connect => Method::Connect,
            Self::Options => Method::Options,
            Self::Trace => Method::Trace,
            Self::Patch => Method::Patch,
        }
    }
}

impl RequestTargetCase {
    fn target(&self) -> Vec<u8> {
        let base = match self.shape {
            TargetShape::Valid => self.valid_target(),
            TargetShape::Empty => Vec::new(),
            TargetShape::SpaceInjected => {
                let mut target = self.valid_target();
                target.extend_from_slice(b" injected");
                target
            }
            TargetShape::ControlInjected => {
                let mut target = self.valid_target();
                target.push(0);
                target
            }
            TargetShape::NonAsciiInjected => {
                let mut target = self.valid_target();
                target.push(0xff);
                target
            }
            TargetShape::DoubleSlashOrigin => b"//ambiguous".to_vec(),
            TargetShape::MissingAbsoluteAuthority => b"http:///path".to_vec(),
            TargetShape::MissingAuthorityHost => b":443".to_vec(),
            TargetShape::MissingAuthorityPort => b"example.com:".to_vec(),
        };
        base
    }

    fn valid_target(&self) -> Vec<u8> {
        match self.form {
            TargetForm::Origin => self.origin_form(),
            TargetForm::Absolute => self.absolute_form(),
            TargetForm::Authority => self.authority_form(),
            TargetForm::Asterisk => b"*".to_vec(),
        }
    }

    fn origin_form(&self) -> Vec<u8> {
        let mut target = Vec::from(&b"/"[..]);
        target.extend(sanitize_component(&self.path_seed, b"resource"));
        let query = sanitize_component(&self.query_seed, b"q=1");
        if !query.is_empty() && self.query_seed.len() % 2 == 1 {
            target.push(b'?');
            target.extend(query);
        }
        target
    }

    fn absolute_form(&self) -> Vec<u8> {
        let mut target = Vec::new();
        target.extend_from_slice(if self.use_https {
            b"https://"
        } else {
            b"http://"
        });
        target.extend(self.authority_form());
        target.extend(self.origin_form());
        target
    }

    fn authority_form(&self) -> Vec<u8> {
        let mut target = sanitize_host(&self.host_seed);
        target.push(b':');
        let port = (self.port_seed % 65_535).max(1);
        target.extend(port.to_string().bytes());
        target
    }

    fn expected_valid(&self) -> bool {
        if self.shape != TargetShape::Valid {
            return false;
        }

        match (self.method, self.form) {
            (FuzzMethod::Connect, TargetForm::Authority)
            | (FuzzMethod::Options, TargetForm::Asterisk) => true,
            (FuzzMethod::Connect, _) | (_, TargetForm::Authority) | (_, TargetForm::Asterisk) => {
                false
            }
            (_, TargetForm::Origin | TargetForm::Absolute) => true,
        }
    }

    fn request_bytes(&self) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(self.method.as_str().as_bytes());
        request.push(b' ');
        request.extend(self.target());
        request.extend_from_slice(b" HTTP/1.1\r\nHost: fuzz.example\r\n\r\n");
        request
    }
}

fn sanitize_host(seed: &[u8]) -> Vec<u8> {
    let mut host = Vec::new();
    for byte in seed.iter().copied().take(MAX_COMPONENT_BYTES) {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' => host.push(byte),
            _ => host.push(b'a' + (byte % 26)),
        }
    }

    if host.is_empty() || host.iter().all(|&b| b == b'.' || b == b'-') {
        host.extend_from_slice(b"example.com");
    }
    host
}

fn sanitize_component(seed: &[u8], fallback: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for byte in seed.iter().copied().take(MAX_COMPONENT_BYTES) {
        match byte {
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'%'
            | b'&'
            | b'='
            | b'+'
            | b',' => out.push(byte),
            _ => out.push(b'a' + (byte % 26)),
        }
    }

    if out.is_empty() {
        out.extend_from_slice(fallback);
    }
    out
}

fn decode_request(raw: &[u8]) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(raw);
    codec.decode(&mut buf)
}

fn assert_valid(case: &RequestTargetCase, raw: &[u8], target: &str) {
    match decode_request(raw) {
        Ok(Some(request)) => {
            assert_eq!(request.method, case.method.expected());
            assert_eq!(request.uri, target);
            assert_eq!(request.version, Version::Http11);
        }
        Ok(None) => panic!("complete request-target form did not decode: {raw:?}"),
        Err(err) => panic!("valid request-target form was rejected: {err:?}; raw={raw:?}"),
    }
}

fn assert_invalid(raw: &[u8]) {
    match decode_request(raw) {
        Ok(Some(request)) => panic!(
            "invalid request-target form decoded as method={:?} uri={:?}; raw={raw:?}",
            request.method, request.uri
        ),
        Ok(None) => panic!("complete invalid request-target form was incomplete: {raw:?}"),
        Err(_) => {}
    }
}

fuzz_target!(|case: RequestTargetCase| {
    let target = case.target();
    let raw = case.request_bytes();

    if case.expected_valid() {
        let target = std::str::from_utf8(&target).expect("valid generated target is ASCII");
        assert_valid(&case, &raw, target);
    } else {
        assert_invalid(&raw);
    }
});
