//! Explicit sender authority for the native ATP data plane.
//!
//! Server-authenticated TLS alone does not authorize a client to publish files.
//! This module installs mandatory WebPKI client authentication plus a bounded
//! exact-certificate allowlist into the real native handshake. No peer label,
//! local session transcript, or certificate fingerprint alone grants access.
//!
//! Authorization covers the receiver's configured destination and operations;
//! it is not a per-path capability grant. Changes affect subsequent handshake
//! verification, not already-established connections. Certificates must be
//! renewed explicitly in the allowlist. There is no implicit system-root load,
//! certificate fetch, permissive fallback, TLS resumption, or early data.

use super::{AtpSdk, NativeTransferClient, NativeTransferError};
use crate::net::atp::transport_quic::native_link::{QuicClientTls, QuicServerTls};
use crate::net::atp::transport_quic::QuicConfig;
use crate::net::quic_native::handshake_driver::ATP_QUIC_ALPN;
use parking_lot::RwLock;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, VerifierBuilderError, WebPkiClientVerifier};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore,
    ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Maximum certificate entries accepted in one authorization configuration.
/// Duplicate entries also count toward the input bound.
pub const MAX_NATIVE_AUTHORIZED_CLIENTS: usize = 1024;

/// SHA-256 of a complete DER leaf certificate, not a public-key-only pin.
///
/// This is an authorization selector. It never substitutes for chain, time,
/// purpose, or proof-of-private-key-possession verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeClientCertificateId([u8; 32]);

impl NativeClientCertificateId {
    /// Compute the selector for an explicitly provisioned client certificate.
    /// Computing a selector does not validate that certificate.
    #[must_use]
    pub fn from_certificate(certificate: &CertificateDer<'_>) -> Self {
        Self(Sha256::digest(certificate.as_ref()).into())
    }

    /// Load an already provisioned complete-certificate SHA-256 selector.
    #[must_use]
    pub const fn from_sha256(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The complete-certificate SHA-256 bytes, suitable for configuration storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Explicit certificate chain (leaf first) and corresponding private key.
/// Debug output deliberately excludes certificates and private-key material.
pub struct NativeTlsIdentity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl std::fmt::Debug for NativeTlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeTlsIdentity")
            .field("certificate_count", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl NativeTlsIdentity {
    /// Retain an explicit identity. TLS configuration construction additionally
    /// checks the key and certificate; the peer validates the chain and purpose.
    ///
    /// # Errors
    /// Rejects an empty certificate chain.
    pub fn new(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, NativeAuthenticationError> {
        if chain.is_empty() {
            return Err(NativeAuthenticationError::EmptyIdentity);
        }
        Ok(Self { chain, key })
    }
}

/// Shared client-certificate authority for one or more native receivers.
///
/// A client must both chain to the explicit roots and match an allowed leaf.
/// An empty allowlist denies every client, including valid CA-issued clients.
/// Clones share live allowlist updates. Root trust is immutable: create a new
/// policy/receiver to change roots. The caller must protect this policy's
/// configuration; it is not inferred from untrusted manifests or peer labels.
#[derive(Clone)]
pub struct NativeClientAuthorization {
    roots: Arc<RootCertStore>,
    allowed: Arc<RwLock<BTreeSet<NativeClientCertificateId>>>,
}

impl std::fmt::Debug for NativeClientAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeClientAuthorization")
            .field("allowed_certificates", &self.allowed_count())
            .finish_non_exhaustive()
    }
}

impl NativeClientAuthorization {
    /// Configure explicit issuer trust and a bounded leaf-certificate allowlist.
    ///
    /// # Errors
    /// Rejects empty trust roots and an oversized input, even if it duplicates
    /// the same selector. No socket is opened and no platform roots are loaded.
    pub fn new(
        roots: RootCertStore,
        allowed: impl IntoIterator<Item = NativeClientCertificateId>,
    ) -> Result<Self, NativeAuthenticationError> {
        if roots.is_empty() {
            return Err(NativeAuthenticationError::EmptyRoots);
        }
        Ok(Self {
            roots: Arc::new(roots),
            allowed: Arc::new(RwLock::new(bounded_ids(allowed)?)),
        })
    }

    /// Atomically replace the allowed certificates for future TLS verification.
    /// An empty iterator suspends all new clients. Existing connections are not
    /// disconnected; a handshake past verification can still finish. Disable
    /// admission and drain existing receivers for a stronger revocation boundary.
    ///
    /// # Errors
    /// An oversized replacement leaves the previous policy unchanged.
    pub fn replace_allowed(
        &self,
        allowed: impl IntoIterator<Item = NativeClientCertificateId>,
    ) -> Result<(), NativeAuthenticationError> {
        let replacement = bounded_ids(allowed)?;
        *self.allowed.write() = replacement;
        Ok(())
    }

    /// Current number of configured selectors; not a count of authenticated peers.
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.allowed.read().len()
    }

    fn check_allowed(&self, certificate: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let id = NativeClientCertificateId::from_certificate(certificate);
        if self.allowed.read().contains(&id) {
            Ok(())
        } else {
            // Do not disclose the allowlist or presented identity in diagnostics.
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
}

fn bounded_ids(
    ids: impl IntoIterator<Item = NativeClientCertificateId>,
) -> Result<BTreeSet<NativeClientCertificateId>, NativeAuthenticationError> {
    let mut allowed = BTreeSet::new();
    for (index, id) in ids.into_iter().enumerate() {
        if index == MAX_NATIVE_AUTHORIZED_CLIENTS {
            return Err(NativeAuthenticationError::TooManyClients);
        }
        allowed.insert(id);
    }
    Ok(allowed)
}

/// Authentication configuration failure, before native socket admission.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeAuthenticationError {
    /// No explicit issuer roots were supplied.
    #[error("native authentication requires explicit nonempty trust roots")]
    EmptyRoots,
    /// No local leaf certificate was supplied.
    #[error("native TLS identity requires a nonempty certificate chain")]
    EmptyIdentity,
    /// The bounded allowlist input was exceeded.
    #[error("native client authorization exceeds its certificate-entry limit")]
    TooManyClients,
    /// TLS configuration, key, or certificate construction failed.
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    /// WebPKI rejected the verifier configuration.
    #[error(transparent)]
    Verifier(#[from] VerifierBuilderError),
    /// Existing native SDK policy or transport configuration refused the client.
    #[error(transparent)]
    Native(#[from] NativeTransferError),
}

#[derive(Debug)]
struct AuthorizedClientVerifier {
    webpki: Arc<dyn ClientCertVerifier>,
    authorization: NativeClientAuthorization,
}

impl ClientCertVerifier for AuthorizedClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.webpki.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self.webpki.verify_client_cert(end_entity, intermediates, now)?;
        self.authorization.check_allowed(end_entity)?;
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let verified = self.webpki.verify_tls12_signature(message, cert, dss)?;
        self.authorization.check_allowed(cert)?;
        Ok(verified)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let verified = self.webpki.verify_tls13_signature(message, cert, dss)?;
        self.authorization.check_allowed(cert)?;
        Ok(verified)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

fn client_tls(
    name: ServerName<'static>,
    roots: RootCertStore,
    identity: NativeTlsIdentity,
) -> Result<QuicClientTls, NativeAuthenticationError> {
    if roots.is_empty() {
        return Err(NativeAuthenticationError::EmptyRoots);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(identity.chain, identity.key)?;
    config.alpn_protocols = vec![ATP_QUIC_ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(QuicClientTls { server_name: name, config: Arc::new(config) })
}

fn server_tls(
    identity: NativeTlsIdentity,
    authorization: NativeClientAuthorization,
) -> Result<QuicServerTls, NativeAuthenticationError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let webpki = WebPkiClientVerifier::builder_with_provider(
        Arc::clone(&authorization.roots), Arc::clone(&provider),
    ).build()?;
    let verifier = Arc::new(AuthorizedClientVerifier { webpki, authorization });
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.chain, identity.key)?;
    config.alpn_protocols = vec![ATP_QUIC_ALPN.to_vec()];
    // A resumed session must not bypass a changed allowlist. This fresh config
    // has no ticketer; do not import either cache or tickets from legacy config.
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Ok(QuicServerTls { config: Arc::new(config) })
}

impl AtpSdk {
    /// Build a sender that presents its explicit identity to an mTLS receiver.
    ///
    /// Server chain/name verification remains standard WebPKI. All existing
    /// native path, buffer, writer and checkpoint sends use this same client
    /// config. A server must use `authorized_native_receiver` (or an equivalent
    /// mandatory verifier) to require and authorize the client certificate.
    /// A server that never asks for client authentication cannot be forced to.
    ///
    /// Existing TLS settings in `config` are replaced, and server TLS is cleared:
    /// this returned native client is sender-only. All other transport limits,
    /// symbol-authentication choices and SDK admission rules remain unchanged.
    ///
    /// # Errors
    /// Rejects invalid identity/trust/TLS configuration or native SDK policy.
    pub fn native_sender_with_identity(
        &self,
        mut config: QuicConfig,
        server_name: ServerName<'static>,
        server_roots: RootCertStore,
        identity: NativeTlsIdentity,
    ) -> Result<NativeTransferClient, NativeAuthenticationError> {
        config.client_tls = Some(client_tls(server_name, server_roots, identity)?);
        config.server_tls = None;
        Ok(self.native_transfers(config)?)
    }

    /// Build a receiver that requires a CA-valid, explicitly allowed client leaf.
    ///
    /// Mandatory client certificate and CertificateVerify checks run in the
    /// existing native TLS handshake, before the ATP application transfer body.
    /// SHA-256 selectors narrow WebPKI trust; they never replace chain, validity,
    /// client-purpose or private-key-possession verification. Anonymous clients
    /// and valid but unlisted clients are rejected. TLS resumption and early
    /// data are disabled so each new connection must authenticate again.
    ///
    /// Hold a clone of `authorization` to replace its allowlist. Changes do not
    /// cancel established sessions. Authorization applies to this receiver's
    /// configured destination; it is not object/path-specific delegation.
    /// Existing TLS settings are replaced and client TLS is cleared, making the
    /// returned native client receiver-only. Transport/SDK limits are preserved.
    ///
    /// # Errors
    /// Rejects invalid identity/verifier/TLS configuration or native SDK policy.
    pub fn authorized_native_receiver(
        &self,
        mut config: QuicConfig,
        identity: NativeTlsIdentity,
        authorization: NativeClientAuthorization,
    ) -> Result<NativeTransferClient, NativeAuthenticationError> {
        config.server_tls = Some(server_tls(identity, authorization)?);
        config.client_tls = None;
        Ok(self.native_transfers(config)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_input_is_bounded_even_for_duplicate_or_infinite_inputs() {
        let id = NativeClientCertificateId::from_sha256([7; 32]);
        assert_eq!(bounded_ids([id, id]).unwrap().len(), 1);
        assert!(bounded_ids(std::iter::repeat_n(id, MAX_NATIVE_AUTHORIZED_CLIENTS)).is_ok());
        assert!(matches!(bounded_ids(std::iter::repeat(id)), Err(NativeAuthenticationError::TooManyClients)));
        assert!(bounded_ids([]).unwrap().is_empty());
    }

    #[test]
    fn complete_certificate_identity_changes_with_any_der_change() {
        let first = CertificateDer::from(vec![1, 2, 3]);
        let second = CertificateDer::from(vec![1, 2, 4]);
        let digest: [u8; 32] = Sha256::digest(first.as_ref()).into();
        assert_eq!(NativeClientCertificateId::from_certificate(&first).as_bytes(), &digest);
        assert_ne!(NativeClientCertificateId::from_certificate(&first), NativeClientCertificateId::from_certificate(&second));
    }

    #[test]
    fn empty_roots_are_never_replaced_with_ambient_trust() {
        assert!(matches!(NativeClientAuthorization::new(RootCertStore::empty(), []), Err(NativeAuthenticationError::EmptyRoots)));
    }

    #[test]
    fn identity_debug_does_not_expose_key_or_certificate_bytes() {
        let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(b"test-key-material".to_vec()));
        let identity = NativeTlsIdentity::new(vec![CertificateDer::from(b"test-certificate-material".to_vec())], key).unwrap();
        let debug = format!("{identity:?}");
        assert!(debug.contains("NativeTlsIdentity"));
        assert!(!debug.contains("material"));
        assert!(!debug.contains("116, 101, 115, 116"));
    }
}
