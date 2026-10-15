//! Structured fuzz target for TLS certificate pinning validation.
//!
//! Focuses on the surfaces behind `TlsConnectorBuilder::with_certificate_pins`
//! and `TlsConnector::with_pin_set`:
//! - malformed DER / PEM certificate blobs
//! - SPKI vs full-certificate pin matching
//! - invalid base64 / wrong-length pin encodings
//! - report-only vs enforce modes
//! - multi-certificate chain inputs bounded to a small root set

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rustls::ClientConfig;
use rustls::crypto::ring::default_provider;
use std::sync::Arc;
use std::time::Duration;

use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, TlsConnector,
    TlsConnectorBuilder, TlsError,
};

const MAX_CERT_SOURCES: usize = 8;
const MAX_CHAIN_CERTS: usize = 8;
const MAX_CERT_BYTES: usize = 16 * 1024;
const MAX_PIN_INPUTS: usize = 32;
const MAX_PIN_BYTES: usize = 128;

#[derive(Arbitrary, Debug)]
struct TlsCertPinningInput {
    cert_sources: Vec<CertificateSource>,
    raw_pins: Vec<RawPinInput>,
    computed_pins: Vec<ComputedPinInput>,
    report_only: bool,
    use_insecure_roots: bool,
    attach_timeout_ms: Option<u16>,
}

#[derive(Arbitrary, Debug)]
enum CertificateSource {
    Der(Vec<u8>),
    Pem(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum PinKind {
    Spki,
    Cert,
}

#[derive(Arbitrary, Debug)]
struct RawPinInput {
    kind: PinKind,
    bytes: Vec<u8>,
    treat_as_base64: bool,
}

#[derive(Arbitrary, Debug)]
struct ComputedPinInput {
    cert_index: u8,
    kind: PinKind,
    flip_byte: Option<u8>,
    roundtrip_base64: bool,
}

fuzz_target!(|input: TlsCertPinningInput| {
    let certs = collect_certificates(&input.cert_sources);
    let pin_set = build_pin_set(&input, &certs);

    exercise_validation(&pin_set, &certs);
    exercise_builder_path(
        &pin_set,
        &certs,
        input.use_insecure_roots,
        input.attach_timeout_ms,
    );
    exercise_raw_connector_path(&pin_set, input.attach_timeout_ms);
});

fn collect_certificates(sources: &[CertificateSource]) -> Vec<Certificate> {
    let mut certs = Vec::new();

    for source in sources.iter().take(MAX_CERT_SOURCES) {
        match source {
            CertificateSource::Der(bytes) => {
                certs.push(Certificate::from_der(clamp_bytes(bytes, MAX_CERT_BYTES)));
            }
            CertificateSource::Pem(bytes) => {
                let pem = clamp_bytes(bytes, MAX_CERT_BYTES);
                if let Ok(parsed) = Certificate::from_pem(&pem) {
                    certs.extend(parsed.into_iter().take(MAX_CHAIN_CERTS));
                }
                certs.push(Certificate::from_der(pem));
            }
        }
    }

    certs.truncate(MAX_CHAIN_CERTS);
    certs
}

fn build_pin_set(input: &TlsCertPinningInput, certs: &[Certificate]) -> CertificatePinSet {
    let mut pin_set = if input.report_only {
        CertificatePinSet::report_only()
    } else {
        CertificatePinSet::new()
    };

    for raw in input.raw_pins.iter().take(MAX_PIN_INPUTS) {
        add_raw_pin(&mut pin_set, raw);
    }

    for computed in input.computed_pins.iter().take(MAX_PIN_INPUTS) {
        if certs.is_empty() {
            break;
        }

        let cert = &certs[usize::from(computed.cert_index) % certs.len()];
        let Ok(mut pin) = compute_pin(cert, computed.kind) else {
            continue;
        };

        if let Some(byte_index) = computed.flip_byte {
            corrupt_pin(&mut pin, byte_index);
        }

        add_pin(&mut pin_set, pin, computed.roundtrip_base64);
    }

    pin_set
}

fn add_raw_pin(pin_set: &mut CertificatePinSet, raw: &RawPinInput) {
    let bytes = clamp_bytes(&raw.bytes, MAX_PIN_BYTES);

    if raw.treat_as_base64 {
        if let Ok(base64ish) = std::str::from_utf8(&bytes) {
            let result = match raw.kind {
                PinKind::Spki => pin_set.add_spki_sha256_base64(base64ish),
                PinKind::Cert => pin_set.add_cert_sha256_base64(base64ish),
            };
            observe_pin_add_result("raw base64 pin", result, pin_set);
        }
        return;
    }

    let pin = match raw.kind {
        PinKind::Spki => CertificatePin::spki_sha256(bytes),
        PinKind::Cert => CertificatePin::cert_sha256(bytes),
    };

    if let Ok(pin) = pin {
        pin_set.add(pin);
    }
}

fn compute_pin(
    cert: &Certificate,
    kind: PinKind,
) -> Result<CertificatePin, asupersync::tls::TlsError> {
    match kind {
        PinKind::Spki => CertificatePin::compute_spki_sha256(cert),
        PinKind::Cert => CertificatePin::compute_cert_sha256(cert),
    }
}

fn corrupt_pin(pin: &mut CertificatePin, byte_index: u8) {
    let bytes = match pin {
        CertificatePin::SpkiSha256(bytes) | CertificatePin::CertSha256(bytes) => bytes,
    };

    if bytes.is_empty() {
        return;
    }

    let index = usize::from(byte_index) % bytes.len();
    let bit = 1_u8 << (byte_index % 8);
    bytes[index] ^= bit;
}

fn add_pin(pin_set: &mut CertificatePinSet, pin: CertificatePin, roundtrip_base64: bool) {
    if !roundtrip_base64 {
        pin_set.add(pin);
        return;
    }

    let encoded = pin.to_base64();
    let decoded = match &pin {
        CertificatePin::SpkiSha256(_) => CertificatePin::spki_sha256_base64(&encoded),
        CertificatePin::CertSha256(_) => CertificatePin::cert_sha256_base64(&encoded),
    };

    if let Ok(decoded) = decoded {
        pin_set.add(decoded);
    }
}

fn exercise_validation(pin_set: &CertificatePinSet, certs: &[Certificate]) {
    let mut inverted_mode = pin_set.clone();
    inverted_mode.set_enforce(!pin_set.is_enforcing());

    for cert in certs {
        observe_pin_compute(
            "SPKI certificate pin",
            CertificatePin::compute_spki_sha256(cert),
            PinKind::Spki,
        );
        observe_pin_compute(
            "full certificate pin",
            CertificatePin::compute_cert_sha256(cert),
            PinKind::Cert,
        );
        observe_pin_validation("configured pin set", pin_set, pin_set.validate(cert));
        observe_pin_validation(
            "inverted pin set",
            &inverted_mode,
            inverted_mode.validate(cert),
        );
    }
}

fn exercise_builder_path(
    pin_set: &CertificatePinSet,
    certs: &[Certificate],
    use_insecure_roots: bool,
    attach_timeout_ms: Option<u16>,
) {
    let mut builder = TlsConnectorBuilder::new().with_certificate_pins(pin_set.clone());

    if let Some(timeout_ms) = attach_timeout_ms {
        builder = builder.handshake_timeout(Duration::from_millis(u64::from(timeout_ms)));
    }

    if use_insecure_roots {
        for cert in certs.iter().take(MAX_CHAIN_CERTS) {
            builder = builder.add_root_certificate(cert);
        }
    } else {
        let mut chain = CertificateChain::new();
        for cert in certs.iter().take(MAX_CHAIN_CERTS) {
            chain.push(cert.clone());
        }
        builder = builder.add_root_certificates(chain);
    }

    observe_builder_result(builder.build(), timeout_from_millis(attach_timeout_ms));
}

fn exercise_raw_connector_path(pin_set: &CertificatePinSet, attach_timeout_ms: Option<u16>) {
    let Ok(builder) = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
    else {
        return;
    };

    let config = builder
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut connector = TlsConnector::new(config).with_pin_set(pin_set.clone());

    if let Some(timeout_ms) = attach_timeout_ms {
        connector = connector.with_handshake_timeout(Duration::from_millis(u64::from(timeout_ms)));
    }

    let expected_timeout = timeout_from_millis(attach_timeout_ms);
    assert_eq!(
        connector.handshake_timeout(),
        expected_timeout,
        "raw connector should retain configured handshake timeout"
    );
    assert!(
        Arc::strong_count(connector.config()) >= 1,
        "raw connector config should remain owned"
    );
}

fn clamp_bytes(bytes: &[u8], max_len: usize) -> Vec<u8> {
    let end = bytes.len().min(max_len);
    bytes[..end].to_vec()
}

fn observe_pin_add_result(
    context: &str,
    result: Result<(), TlsError>,
    pin_set: &CertificatePinSet,
) {
    assert!(
        pin_set.len() <= MAX_PIN_INPUTS,
        "{context} should keep pin set bounded"
    );
    match result {
        Ok(()) => {
            assert!(
                pin_set.iter().all(|pin| pin.hash_bytes().len() == 32),
                "{context} should only admit SHA-256-length pins"
            );
        }
        Err(error) => assert_tls_error_visible(context, &error),
    }
}

fn observe_pin_compute(context: &str, result: Result<CertificatePin, TlsError>, kind: PinKind) {
    match result {
        Ok(pin) => {
            let expected_kind = matches!(
                (&pin, kind),
                (CertificatePin::SpkiSha256(_), PinKind::Spki)
                    | (CertificatePin::CertSha256(_), PinKind::Cert)
            );
            assert!(
                expected_kind,
                "{context} should return the requested pin kind"
            );
            assert_eq!(
                pin.hash_bytes().len(),
                32,
                "{context} should compute a SHA-256-length hash"
            );
            assert!(
                !pin.to_base64().is_empty(),
                "{context} should expose a base64 representation"
            );
        }
        Err(error) => assert_tls_error_visible(context, &error),
    }
}

fn observe_pin_validation(
    context: &str,
    pin_set: &CertificatePinSet,
    result: Result<bool, TlsError>,
) {
    match result {
        Ok(matched) => {
            if pin_set.is_empty() {
                assert!(matched, "{context} should accept empty pin sets");
            }
            if !pin_set.is_enforcing() && !matched {
                assert!(
                    !pin_set.is_empty(),
                    "{context} should only report mismatch when pins exist"
                );
            }
        }
        Err(error) => {
            assert!(
                pin_set.is_enforcing() && !pin_set.is_empty(),
                "{context} should fail closed only for enforcing non-empty pin sets"
            );
            assert_tls_error_visible(context, &error);
        }
    }
}

fn observe_builder_result(
    result: Result<TlsConnector, TlsError>,
    expected_timeout: Option<Duration>,
) {
    match result {
        Ok(connector) => {
            assert_eq!(
                connector.handshake_timeout(),
                expected_timeout,
                "builder connector should retain configured handshake timeout"
            );
            assert!(
                Arc::strong_count(connector.config()) >= 1,
                "builder connector config should remain owned"
            );
        }
        Err(error) => assert_tls_error_visible("builder result", &error),
    }
}

fn timeout_from_millis(timeout_ms: Option<u16>) -> Option<Duration> {
    timeout_ms.map(|millis| Duration::from_millis(u64::from(millis)))
}

fn assert_tls_error_visible(context: &str, error: &TlsError) {
    let diagnostic = format!("{error:?}");
    assert!(
        !diagnostic.is_empty(),
        "{context} failure should expose diagnostics"
    );
}
