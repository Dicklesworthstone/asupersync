//! PostgreSQL trust policy, kept separate from the exhaustively constructible
//! connection options that predate explicit TLS verification modes.

#[cfg(feature = "tls")]
use super::PgError;
use crate::tls::Certificate;
use std::path::PathBuf;
use std::time::Duration;

/// Certificate checks performed for a PostgreSQL TLS connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PgTlsVerification {
    /// Verify the certificate chain, validity, and server-authentication usage.
    /// The certificate name is deliberately not checked, matching `verify-ca`.
    VerifyCa,
    /// Also verify the host against the certificate's DNS or IP subject
    /// alternative names. Rustls does not use libpq's legacy Common Name fallback.
    #[default]
    VerifyFull,
}

/// Additive PostgreSQL TLS options.
///
/// Explicit roots replace ambient and public roots. With no explicit roots,
/// the established `tls-webpki-roots` plus `SSL_CERT_FILE` behavior is retained.
/// Both verification modes check certificates and handshake signatures through
/// rustls; neither permits an unverified certificate. Revocation lists and
/// libpq's implicit `~/.postgresql/root.crt` lookup are not configured here.
///
/// Use [`Self::verification`] to require TLS, or set the connection's
/// [`super::SslMode`] to `Require`. A root certificate alone does not change
/// an explicitly selected `Prefer` mode's plaintext fallback.
///
/// ```ignore
/// use asupersync::database::postgres::{PgConnectOptions, PgConnection, PgTlsOptions, PgTlsVerification};
/// use std::time::Duration;
/// let options = PgConnectOptions::parse("postgres://user:password@db.internal/app")?;
/// let tls = PgTlsOptions::new()
///     .root_certificate_file("/etc/app/database-ca.pem")
///     .verification(PgTlsVerification::VerifyFull)
///     .connect_timeout(Duration::from_secs(5));
/// let connection = PgConnection::connect_with_tls_options(cx, options, tls).await;
/// ```
#[derive(Debug, Clone)]
pub struct PgTlsOptions {
    verification: PgTlsVerification,
    root_certificate_file: Option<PathBuf>,
    root_certificates: Vec<Certificate>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    require_tls: bool,
}

impl Default for PgTlsOptions {
    fn default() -> Self {
        Self {
            verification: PgTlsVerification::VerifyFull,
            root_certificate_file: None,
            root_certificates: Vec::new(),
            connect_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            require_tls: false,
        }
    }
}

impl PgTlsOptions {
    /// Create the default host-verifying policy with a ten-second TLS bound
    /// and a thirty-second whole-connect bound.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Require TLS and select certificate verification semantics.
    #[must_use]
    pub fn verification(mut self, verification: PgTlsVerification) -> Self {
        self.verification = verification;
        self.require_tls = true;
        self
    }

    /// Trust a PEM CA bundle, corresponding to libpq's `sslrootcert` option.
    /// Explicit files and certificates form the entire trust store, excluding
    /// `SSL_CERT_FILE` and public roots. An unreadable or invalid file fails closed.
    #[must_use]
    pub fn root_certificate_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.root_certificate_file = Some(path.into());
        self
    }

    /// Add an explicitly trusted CA certificate without reading a file.
    #[must_use]
    pub fn root_certificate(mut self, certificate: Certificate) -> Self {
        self.root_certificates.push(certificate);
        self
    }

    /// Whether the policy replaces ambient/public roots with explicit trust.
    #[must_use]
    pub fn has_explicit_roots(&self) -> bool {
        self.root_certificate_file.is_some() || !self.root_certificates.is_empty()
    }

    /// Bound the entire SSLRequest, server response, and TLS handshake exchange.
    /// A smaller connection timeout further limits this bound. Zero expires
    /// before sending an SSLRequest; there is no unbounded setting.
    #[must_use]
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Bound DNS, TCP, TLS, PostgreSQL startup, and authentication together.
    /// Defaults to thirty seconds. The legacy connection option's
    /// `connect_timeout`, when present, takes precedence over this value.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Return the whole-connect bound used when the legacy option is absent.
    #[must_use]
    pub const fn connect_timeout_duration(&self) -> Duration {
        self.connect_timeout
    }

    /// Return the selected certificate policy.
    #[must_use]
    pub const fn verification_mode(&self) -> PgTlsVerification {
        self.verification
    }

    /// Return the configured TLS exchange bound.
    #[must_use]
    pub const fn handshake_timeout_duration(&self) -> Duration {
        self.handshake_timeout
    }

    pub(super) const fn requires_tls(&self) -> bool {
        self.require_tls
    }

    #[cfg(feature = "tls")]
    pub(super) fn build_connector(&self) -> Result<crate::tls::TlsConnector, PgError> {
        use crate::tls::RootCertStore;
        use std::sync::Arc;

        let explicit = self.has_explicit_roots();
        let mut roots = RootCertStore::empty();
        let mut certificates = self.root_certificates.clone();
        if let Some(path) = &self.root_certificate_file {
            certificates.extend(Certificate::from_pem_file(path).map_err(|err| {
                PgError::Tls(format!("loading sslrootcert {}: {err}", path.display()))
            })?);
        }
        if !explicit {
            roots.extend_from_webpki_roots();
            if let Ok(path) = std::env::var("SSL_CERT_FILE") {
                certificates.extend(
                    Certificate::from_pem_file(&path).map_err(|err| {
                        PgError::Tls(format!("loading SSL_CERT_FILE {path}: {err}"))
                    })?,
                );
            }
        }
        for certificate in certificates {
            // Preserve the existing strict CA constraint. Trusting a leaf as
            // a CA must not bypass normal end-entity certificate validation.
            let is_ca = x509_parser::parse_x509_certificate(certificate.as_der())
                .ok()
                .and_then(|(_, cert)| {
                    cert.basic_constraints()
                        .ok()
                        .flatten()
                        .map(|bc| bc.value.ca)
                })
                .unwrap_or(false);
            if !is_ca {
                if explicit {
                    return Err(PgError::Tls(
                        "sslrootcert contains a non-CA certificate".into(),
                    ));
                }
                continue;
            }
            roots
                .add(&certificate)
                .map_err(|err| PgError::Tls(err.to_string()))?;
        }
        if roots.is_empty() {
            return Err(PgError::Tls(
                "no PostgreSQL TLS trust roots; configure sslrootcert or explicit CA certificates, \
                 or enable tls-webpki-roots"
                    .into(),
            ));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let algorithms = provider.signature_verification_algorithms;
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|err| PgError::Tls(err.to_string()))?;
        let roots = roots.into_inner();
        let builder = match self.verification {
            PgTlsVerification::VerifyFull => builder.with_root_certificates(roots),
            PgTlsVerification::VerifyCa => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(CaVerifier { roots, algorithms })),
        };
        Ok(crate::tls::TlsConnector::new(builder.with_no_client_auth()))
    }
}

/// The only difference from full verification is the deliberate omission of
/// `verify_server_name`. Rustls still verifies chain constraints, validity,
/// serverAuth usage, and TLS 1.2/1.3 CertificateVerify signatures.
#[cfg(feature = "tls")]
#[derive(Debug)]
struct CaVerifier {
    roots: rustls::RootCertStore,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

#[cfg(feature = "tls")]
impl rustls::client::danger::ServerCertVerifier for CaVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let certificate = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &certificate,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
