//! Durable identity key storage for ATP peers.
//!
//! The store persists NKey user seeds with a small canonical JSON record. All
//! creation and rotation APIs take caller-provided entropy and timestamps so ATP
//! daemon code can keep randomness and clocks capability-explicit.

// The owned NKey codec is staged behind the library test configuration until
// its full text/prefix substrate reaches the terminal N2 gate. Production
// identity operations continue to use the incumbent `nkeys` crate.
#[cfg(test)]
mod nkey_codec;

use nkeys::{KeyPair, KeyPairType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use zeroize::Zeroize;

const KEY_STORE_SCHEMA_VERSION: u32 = 1;
const FINGERPRINT_DOMAIN: &[u8] = b"ATP-IDENTITY-KEY-FINGERPRINT-V1\0";
// Seed-entropy sanity thresholds for 32-byte Ed25519 user seeds. Kept in parity
// with the hardened `AuthKey` strength validator (`security::key`: 16/64/192,
// br-asupersync-q3terg) so both identity-key paths reject the same class of
// pathologically-low-entropy material (aasraf). These are a sanity guard, not
// the security boundary — seeds come from a capability-explicit CSPRNG seam.
const MIN_SEED_DISTINCT_BYTES: usize = 16;
const MIN_SEED_HAMMING_WEIGHT: u32 = 64;
const MAX_SEED_HAMMING_WEIGHT: u32 = 192;

/// Stable fingerprint for a public identity key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyFingerprint([u8; 32]);

impl KeyFingerprint {
    /// Derive the canonical fingerprint from public key material.
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, KeyStoreError> {
        if public_key.is_empty() {
            return Err(KeyStoreError::InvalidPublicKey(
                "public key material is empty".to_string(),
            ));
        }
        if public_key.iter().all(|byte| *byte == 0) {
            return Err(KeyStoreError::InvalidPublicKey(
                "public key material is all zero".to_string(),
            ));
        }
        Ok(Self::from_public_key_unchecked(public_key))
    }

    fn from_public_key_unchecked(public_key: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update((public_key.len() as u64).to_be_bytes());
        hasher.update(public_key);
        Self(hasher.finalize().into())
    }

    /// Decode a hex-encoded fingerprint.
    pub fn from_hex(encoded: &str) -> Result<Self, KeyStoreError> {
        let bytes = hex::decode(encoded).map_err(|err| {
            KeyStoreError::InvalidFingerprint(format!("fingerprint is not valid hex: {err}"))
        })?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            KeyStoreError::InvalidFingerprint(format!(
                "fingerprint has {} bytes, expected 32",
                bytes.len()
            ))
        })?;
        Ok(Self(bytes))
    }

    /// Return the canonical fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Return the full lowercase hex encoding.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Return a short diagnostic prefix.
    #[must_use]
    pub fn redacted(self) -> String {
        hex::encode(&self.0[..8])
    }
}

impl fmt::Debug for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyFingerprint")
            .field(&self.redacted())
            .finish()
    }
}

impl fmt::Display for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Raw byte width of an NKey Ed25519 public key, Ed25519 seed, or X25519 key.
pub const NKEY_KEY_BYTES: usize = 32;
/// Raw byte width of an expanded Ed25519 private key.
pub const NKEY_ED25519_PRIVATE_BYTES: usize = 64;

/// The role carried by a typed Ed25519 NKey.
///
/// Curve/X25519 keys deliberately have a separate owned type and therefore
/// cannot be represented by this enum. Parsing is exact and never falls back
/// to another role for an unknown name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NkeyEd25519Kind {
    /// Account identity or explicitly authorized Account signing key.
    Account,
    /// Cluster identity; no NATS JWT hierarchy authority.
    Cluster,
    /// Rust Module extension; no NATS JWT hierarchy authority.
    Module,
    /// Server identity; no Operator/Account/User JWT hierarchy authority.
    Server,
    /// Operator identity or explicitly authorized Operator signing key.
    Operator,
    /// User identity used for server-nonce authentication, never JWT issuance.
    User,
    /// Rust Service extension; no NATS JWT hierarchy authority.
    Service,
}

impl NkeyEd25519Kind {
    /// Return the canonical one-letter public-key symbol.
    #[must_use]
    pub const fn symbol(self) -> char {
        match self {
            Self::Account => 'A',
            Self::Cluster => 'C',
            Self::Module => 'M',
            Self::Server => 'N',
            Self::Operator => 'O',
            Self::User => 'U',
            Self::Service => 'V',
        }
    }

    /// Return the canonical NKey public-prefix byte.
    #[must_use]
    pub const fn prefix_byte(self) -> u8 {
        match self {
            Self::Account => 0,
            Self::Cluster => 16,
            Self::Module => 96,
            Self::Server => 104,
            Self::Operator => 112,
            Self::User => 160,
            Self::Service => 168,
        }
    }
}

impl fmt::Display for NkeyEd25519Kind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Account => "Account",
            Self::Cluster => "Cluster",
            Self::Module => "Module",
            Self::Server => "Server",
            Self::Operator => "Operator",
            Self::User => "User",
            Self::Service => "Service",
        })
    }
}

impl FromStr for NkeyEd25519Kind {
    type Err = NkeyOwnedKeyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "A" | "Account" => Ok(Self::Account),
            "C" | "Cluster" => Ok(Self::Cluster),
            "M" | "Module" => Ok(Self::Module),
            "N" | "Server" => Ok(Self::Server),
            "O" | "Operator" => Ok(Self::Operator),
            "U" | "User" => Ok(Self::User),
            "V" | "Service" => Ok(Self::Service),
            _ => Err(NkeyOwnedKeyError::UnknownEd25519Kind {
                actual_len: input.len(),
            }),
        }
    }
}

/// Stable owned-key form used in diagnostics without exposing key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NkeyOwnedKeyForm {
    /// Typed Ed25519 public material.
    Ed25519Public,
    /// Typed Ed25519 seed material.
    Ed25519Seed,
    /// Typed expanded Ed25519 private material.
    Ed25519Private,
    /// Curve/X25519 public material.
    CurvePublic,
    /// Curve/X25519 secret material.
    CurveSecret,
}

impl fmt::Display for NkeyOwnedKeyForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ed25519Public => "ed25519-public",
            Self::Ed25519Seed => "ed25519-seed",
            Self::Ed25519Private => "ed25519-private",
            Self::CurvePublic => "curve-public",
            Self::CurveSecret => "curve-secret",
        })
    }
}

/// Explicit purpose required before copying secret bytes out of an owned key.
///
/// This enum is an intent marker, not an authorization capability. It makes
/// plaintext export, serialization, and persistence visible at the call site.
/// The returned export guard zeroizes its own copy on drop, but cannot erase
/// caller-created copies, allocator remnants, compiler temporaries, registers,
/// swap, crash dumps, or storage written by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NkeySecretDisposition {
    /// Secret remains inside the owned key for a cryptographic operation.
    InProcessOperation,
    /// Caller explicitly requests a transient plaintext copy.
    PlaintextExport,
    /// Caller explicitly requests bytes for plaintext serialization.
    PlaintextSerialization,
    /// Caller explicitly requests bytes for plaintext persistence.
    PlaintextPersistence,
}

impl NkeySecretDisposition {
    const fn permits_export(self) -> bool {
        !matches!(self, Self::InProcessOperation)
    }
}

/// Safe, non-secret diagnostic failures for owned NKey construction/use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NkeyOwnedKeyError {
    /// Raw material had the wrong byte length for the selected owned form.
    Length {
        /// Form whose constructor rejected the input.
        form: NkeyOwnedKeyForm,
        /// Observed byte length.
        actual: usize,
        /// Exact required byte length.
        expected: usize,
    },
    /// A textual Ed25519 role was not one of the exact supported names/symbols.
    UnknownEd25519Kind {
        /// Input length only; the untrusted text is deliberately omitted.
        actual_len: usize,
    },
    /// The requested disposition does not permit a plaintext secret copy.
    SecretDisposition {
        /// Rejected disposition intent.
        disposition: NkeySecretDisposition,
    },
}

impl fmt::Display for NkeyOwnedKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length {
                form,
                actual,
                expected,
            } => write!(
                formatter,
                "{form} key material has {actual} bytes; expected {expected}"
            ),
            Self::UnknownEd25519Kind { actual_len } => write!(
                formatter,
                "unknown Ed25519 NKey kind with {actual_len} input bytes"
            ),
            Self::SecretDisposition { disposition } => write!(
                formatter,
                "secret export is not permitted for disposition {disposition:?}"
            ),
        }
    }
}

impl std::error::Error for NkeyOwnedKeyError {}

struct NkeySecretBytes<const N: usize>([u8; N]);

impl<const N: usize> NkeySecretBytes<N> {
    const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    fn export(
        &self,
        disposition: NkeySecretDisposition,
    ) -> Result<NkeySecretExport<N>, NkeyOwnedKeyError> {
        if !disposition.permits_export() {
            return Err(NkeyOwnedKeyError::SecretDisposition { disposition });
        }
        Ok(NkeySecretExport {
            bytes: self.0,
            disposition,
        })
    }
}

impl<const N: usize> Zeroize for NkeySecretBytes<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Drop for NkeySecretBytes<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Explicit transient plaintext copy of secret NKey material.
///
/// This guard is neither `Copy` nor `Clone`, redacts formatting, and zeroizes
/// its own byte array on drop. [`NkeySecretExport::as_bytes`] is intentionally
/// explicit because any caller-created copy is outside this guard's erasure
/// guarantee.
pub struct NkeySecretExport<const N: usize> {
    bytes: [u8; N],
    disposition: NkeySecretDisposition,
}

impl<const N: usize> NkeySecretExport<N> {
    /// Return the explicit disposition that authorized this transient copy.
    #[must_use]
    pub const fn disposition(&self) -> NkeySecretDisposition {
        self.disposition
    }

    /// Borrow the exported plaintext bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> Zeroize for NkeySecretExport<N> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<const N: usize> Drop for NkeySecretExport<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> fmt::Debug for NkeySecretExport<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NkeySecretExport")
            .field("bytes", &"<redacted>")
            .field("length", &N)
            .field("disposition", &self.disposition)
            .finish()
    }
}

impl<const N: usize> fmt::Display for NkeySecretExport<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<redacted NKey secret: {N} bytes>")
    }
}

fn exact_array<const N: usize>(
    form: NkeyOwnedKeyForm,
    bytes: &[u8],
) -> Result<[u8; N], NkeyOwnedKeyError> {
    bytes.try_into().map_err(|_| NkeyOwnedKeyError::Length {
        form,
        actual: bytes.len(),
        expected: N,
    })
}

/// Owned, typed Ed25519 public verification key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NkeyEd25519PublicKey {
    kind: NkeyEd25519Kind,
    bytes: [u8; NKEY_KEY_BYTES],
}

impl NkeyEd25519PublicKey {
    /// Construct from exact raw public bytes and an explicit role.
    #[must_use]
    pub const fn from_bytes(kind: NkeyEd25519Kind, bytes: [u8; NKEY_KEY_BYTES]) -> Self {
        Self { kind, bytes }
    }

    /// Construct from a byte slice, rejecting every non-exact length.
    pub fn try_from_slice(kind: NkeyEd25519Kind, bytes: &[u8]) -> Result<Self, NkeyOwnedKeyError> {
        Ok(Self::from_bytes(
            kind,
            exact_array(NkeyOwnedKeyForm::Ed25519Public, bytes)?,
        ))
    }

    /// Return the explicit Ed25519 role.
    #[must_use]
    pub const fn kind(self) -> NkeyEd25519Kind {
        self.kind
    }

    /// Borrow the public bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NKEY_KEY_BYTES] {
        &self.bytes
    }

    /// Consume the public key and return its non-secret bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; NKEY_KEY_BYTES] {
        self.bytes
    }
}

impl fmt::Debug for NkeyEd25519PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NkeyEd25519PublicKey")
            .field("kind", &self.kind)
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// Owned, typed Ed25519 seed material.
///
/// The type deliberately does not implement `Copy`, `Clone`, equality, or
/// `serde::Serialize`. Plaintext extraction requires an explicit
/// [`NkeySecretDisposition`].
///
/// Drop zeroizes only this value's narrow internal byte array. Construction
/// copies caller-provided bytes; callers remain responsible for erasing their
/// source buffer and any other copies, allocator remnants, compiler
/// temporaries, registers, swap, crash dumps, or persisted representations.
///
/// ```compile_fail
/// use asupersync::security::{NkeyEd25519Kind, NkeyEd25519Seed};
/// let seed = NkeyEd25519Seed::from_bytes(NkeyEd25519Kind::User, [7; 32]);
/// let duplicate = seed.clone();
/// # let _ = duplicate;
/// ```
///
/// ```compile_fail
/// use asupersync::security::NkeyEd25519Seed;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<NkeyEd25519Seed>();
/// ```
pub struct NkeyEd25519Seed {
    kind: NkeyEd25519Kind,
    secret: NkeySecretBytes<NKEY_KEY_BYTES>,
}

impl NkeyEd25519Seed {
    /// Construct from exact seed bytes and an explicit Ed25519 role.
    #[must_use]
    pub const fn from_bytes(kind: NkeyEd25519Kind, bytes: [u8; NKEY_KEY_BYTES]) -> Self {
        Self {
            kind,
            secret: NkeySecretBytes::new(bytes),
        }
    }

    /// Construct from a byte slice, rejecting every non-exact length.
    pub fn try_from_slice(kind: NkeyEd25519Kind, bytes: &[u8]) -> Result<Self, NkeyOwnedKeyError> {
        Ok(Self::from_bytes(
            kind,
            exact_array(NkeyOwnedKeyForm::Ed25519Seed, bytes)?,
        ))
    }

    /// Return the explicit Ed25519 role without exposing secret bytes.
    #[must_use]
    pub const fn kind(&self) -> NkeyEd25519Kind {
        self.kind
    }

    /// Create a zeroizing transient plaintext copy for an explicit purpose.
    pub fn export_secret(
        &self,
        disposition: NkeySecretDisposition,
    ) -> Result<NkeySecretExport<NKEY_KEY_BYTES>, NkeyOwnedKeyError> {
        self.secret.export(disposition)
    }
}

impl fmt::Debug for NkeyEd25519Seed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NkeyEd25519Seed")
            .field("kind", &self.kind)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for NkeyEd25519Seed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<redacted {} Ed25519 NKey seed>", self.kind)
    }
}

/// Owned, explicitly typed 64-byte expanded Ed25519 private material.
///
/// Drop zeroizes only this value's narrow internal byte array. Construction
/// copies caller-provided bytes; callers remain responsible for erasing their
/// source buffer and any other copies, allocator remnants, compiler
/// temporaries, registers, swap, crash dumps, or persisted representations.
pub struct NkeyEd25519PrivateKey {
    kind: NkeyEd25519Kind,
    secret: NkeySecretBytes<NKEY_ED25519_PRIVATE_BYTES>,
}

impl NkeyEd25519PrivateKey {
    /// Import expanded private material only with an explicit Ed25519 role.
    #[must_use]
    pub const fn from_bytes(
        kind: NkeyEd25519Kind,
        bytes: [u8; NKEY_ED25519_PRIVATE_BYTES],
    ) -> Self {
        Self {
            kind,
            secret: NkeySecretBytes::new(bytes),
        }
    }

    /// Import a byte slice, rejecting every non-exact length.
    pub fn try_from_slice(kind: NkeyEd25519Kind, bytes: &[u8]) -> Result<Self, NkeyOwnedKeyError> {
        Ok(Self::from_bytes(
            kind,
            exact_array(NkeyOwnedKeyForm::Ed25519Private, bytes)?,
        ))
    }

    /// Return the explicit Ed25519 role without exposing secret bytes.
    #[must_use]
    pub const fn kind(&self) -> NkeyEd25519Kind {
        self.kind
    }

    /// Create a zeroizing transient plaintext copy for an explicit purpose.
    pub fn export_secret(
        &self,
        disposition: NkeySecretDisposition,
    ) -> Result<NkeySecretExport<NKEY_ED25519_PRIVATE_BYTES>, NkeyOwnedKeyError> {
        self.secret.export(disposition)
    }
}

impl fmt::Debug for NkeyEd25519PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NkeyEd25519PrivateKey")
            .field("kind", &self.kind)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for NkeyEd25519PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<redacted {} Ed25519 private key>", self.kind)
    }
}

/// Owned Curve/X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NkeyCurvePublicKey([u8; NKEY_KEY_BYTES]);

impl NkeyCurvePublicKey {
    /// Construct from exact raw X25519 public bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NKEY_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Construct from a byte slice, rejecting every non-exact length.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, NkeyOwnedKeyError> {
        Ok(Self::from_bytes(exact_array(
            NkeyOwnedKeyForm::CurvePublic,
            bytes,
        )?))
    }

    /// Borrow the non-secret public bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NKEY_KEY_BYTES] {
        &self.0
    }

    /// Consume the public key and return its non-secret bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; NKEY_KEY_BYTES] {
        self.0
    }
}

impl fmt::Debug for NkeyCurvePublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NkeyCurvePublicKey")
            .field(&self.0)
            .finish()
    }
}

/// Owned Curve/X25519 secret material.
///
/// This type is separate from every Ed25519 signing form and cannot satisfy
/// [`NkeyEd25519SigningMaterial`].
///
/// Drop zeroizes only this value's narrow internal byte array. Construction
/// copies caller-provided bytes; callers remain responsible for erasing their
/// source buffer and any other copies, allocator remnants, compiler
/// temporaries, registers, swap, crash dumps, or persisted representations.
///
/// ```compile_fail
/// use asupersync::security::{NkeyCurveSecretKey, NkeyEd25519SigningMaterial};
/// fn requires_ed25519<T: NkeyEd25519SigningMaterial>(_: &T) {}
/// let curve = NkeyCurveSecretKey::from_bytes([9; 32]);
/// requires_ed25519(&curve);
/// ```
pub struct NkeyCurveSecretKey(NkeySecretBytes<NKEY_KEY_BYTES>);

impl NkeyCurveSecretKey {
    /// Construct from exact raw X25519 secret bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NKEY_KEY_BYTES]) -> Self {
        Self(NkeySecretBytes::new(bytes))
    }

    /// Construct from a byte slice, rejecting every non-exact length.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, NkeyOwnedKeyError> {
        Ok(Self::from_bytes(exact_array(
            NkeyOwnedKeyForm::CurveSecret,
            bytes,
        )?))
    }

    /// Create a zeroizing transient plaintext copy for an explicit purpose.
    pub fn export_secret(
        &self,
        disposition: NkeySecretDisposition,
    ) -> Result<NkeySecretExport<NKEY_KEY_BYTES>, NkeyOwnedKeyError> {
        self.0.export(disposition)
    }
}

impl fmt::Debug for NkeyCurveSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NkeyCurveSecretKey(<redacted>)")
    }
}

impl fmt::Display for NkeyCurveSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted Curve/X25519 secret key>")
    }
}

mod nkey_owned_type_sealed {
    pub trait Sealed {}
}

/// Marker implemented only by owned Ed25519 secret signing material.
///
/// It intentionally has no signing operation yet: N5 owns the audited
/// Ed25519 operation boundary. N3 uses this sealed marker to make Curve keys
/// statically ineligible for future signing APIs.
#[allow(private_bounds)]
pub trait NkeyEd25519SigningMaterial: nkey_owned_type_sealed::Sealed {
    /// Return the explicit signing role without exposing secret bytes.
    fn kind(&self) -> NkeyEd25519Kind;
}

impl nkey_owned_type_sealed::Sealed for NkeyEd25519Seed {}
impl NkeyEd25519SigningMaterial for NkeyEd25519Seed {
    fn kind(&self) -> NkeyEd25519Kind {
        self.kind
    }
}

impl nkey_owned_type_sealed::Sealed for NkeyEd25519PrivateKey {}
impl NkeyEd25519SigningMaterial for NkeyEd25519PrivateKey {
    fn kind(&self) -> NkeyEd25519Kind {
        self.kind
    }
}

/// Public view of an identity key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentityKey {
    /// Monotonic key generation.
    pub generation: u64,
    /// Public NKey value.
    pub public_key: String,
    /// Canonical public-key fingerprint.
    pub fingerprint: KeyFingerprint,
    /// Whether this generation has been revoked.
    pub revoked: bool,
}

/// Wire width of an [`IdentityTranscriptSignature`].
pub const IDENTITY_TRANSCRIPT_SIGNATURE_BYTES: usize = 105;

const IDENTITY_TRANSCRIPT_DOMAIN: &[u8] = b"ASUPERSYNC-IDENTITY-TRANSCRIPT-V1\0";
const MAX_TRANSCRIPT_DOMAIN_BYTES: usize = 255;

/// An explicit, versioned identity-transcript signing algorithm.
///
/// The implementation uses the existing NKey Ed25519 primitive. This additive
/// interface does not replace the NKey codec or authorize a JWT issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TranscriptSigningProfile {
    /// Ed25519 over the SHA-256 digest of the framed identity transcript.
    /// This is an application-level digest profile, not RFC 8032 Ed25519ph.
    Ed25519Sha256V1,
}

impl TranscriptSigningProfile {
    /// Return the stable wire identifier.
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        match self {
            Self::Ed25519Sha256V1 => 1,
        }
    }

    /// Parse an exact profile identifier without an algorithm fallback.
    pub fn from_wire_id(id: u8) -> Result<Self, IdentityTranscriptError> {
        match id {
            1 => Ok(Self::Ed25519Sha256V1),
            _ => Err(IdentityTranscriptError::UnknownProfile(id)),
        }
    }
}

/// Redacted failures at the identity-transcript boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityTranscriptError {
    /// No implementation is registered for the supplied wire profile.
    #[error("unsupported identity transcript signing profile: {0}")]
    UnknownProfile(u8),
    /// The signature envelope does not have its exact fixed width.
    #[error("identity transcript signature has {actual} bytes, expected 105")]
    SignatureLength {
        /// Supplied envelope length; the bytes themselves are never echoed.
        actual: usize,
    },
    /// Generation zero is never issued by an identity key store.
    #[error("identity transcript key generation must be nonzero")]
    InvalidGeneration,
    /// The supplied key is not a canonical public User NKey.
    #[error("invalid identity transcript public key")]
    PublicKey,
    /// Public key bytes and the supplied fingerprint do not agree.
    #[error("identity transcript public-key fingerprint mismatch")]
    FingerprintMismatch,
    /// This key generation has been explicitly revoked.
    #[error("identity transcript key generation is revoked")]
    Revoked,
    /// The supplied generation is not the currently trusted generation.
    #[error("identity transcript key generation is retired or not currently trusted")]
    InactiveGeneration,
    /// The signature names another pinned key or generation.
    #[error("identity transcript signature does not match the pinned identity")]
    IdentityMismatch,
    /// The signature names another pinned algorithm profile.
    #[error("identity transcript signature profile mismatch")]
    ProfileMismatch,
    /// Application domains must be nonempty and at most 255 bytes.
    #[error("identity transcript domain must contain 1 to 255 bytes")]
    Domain,
    /// The transcript cannot be represented by the profile's length field.
    #[error("identity transcript length exceeds the signing profile")]
    TranscriptLength,
    /// The loaded key store could not provide its active signing identity.
    #[error("identity transcript signing key is unavailable")]
    KeyUnavailable,
    /// The incumbent primitive could not produce a signature.
    #[error("identity transcript signing failed")]
    Signing,
    /// The signature does not authenticate the exact supplied transcript.
    #[error("identity transcript signature verification failed")]
    Verification,
}

/// An opaque, public signature bound to a profile and identity generation.
///
/// The wire format is exactly: one profile byte, a big-endian u64
/// generation, 32 fingerprint bytes, and 64 Ed25519 signature bytes.
/// Parsing establishes framing only; call a trusted verification key or the
/// current [`IdentityKeyStore`] to authenticate the envelope and transcript.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentityTranscriptSignature {
    profile: TranscriptSigningProfile,
    generation: u64,
    fingerprint: KeyFingerprint,
    signature: [u8; 64],
}

impl IdentityTranscriptSignature {
    /// Decode an exact-width signature, refusing unknown algorithm profiles.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityTranscriptError> {
        let bytes: &[u8; IDENTITY_TRANSCRIPT_SIGNATURE_BYTES] = bytes
            .try_into()
            .map_err(|_| IdentityTranscriptError::SignatureLength { actual: bytes.len() })?;
        let profile = TranscriptSigningProfile::from_wire_id(bytes[0])?;
        let mut generation = [0; 8];
        generation.copy_from_slice(&bytes[1..9]);
        let generation = u64::from_be_bytes(generation);
        if generation == 0 {
            return Err(IdentityTranscriptError::InvalidGeneration);
        }
        let mut fingerprint = [0; 32];
        fingerprint.copy_from_slice(&bytes[9..41]);
        let mut signature = [0; 64];
        signature.copy_from_slice(&bytes[41..]);
        Ok(Self {
            profile,
            generation,
            fingerprint: KeyFingerprint(fingerprint),
            signature,
        })
    }

    /// Encode the complete public signature without exposing key material.
    #[must_use]
    pub fn to_bytes(self) -> [u8; IDENTITY_TRANSCRIPT_SIGNATURE_BYTES] {
        let mut bytes = [0; IDENTITY_TRANSCRIPT_SIGNATURE_BYTES];
        bytes[0] = self.profile.wire_id();
        bytes[1..9].copy_from_slice(&self.generation.to_be_bytes());
        bytes[9..41].copy_from_slice(&self.fingerprint.as_bytes());
        bytes[41..].copy_from_slice(&self.signature);
        bytes
    }

    /// Return the exact signing profile.
    #[must_use]
    pub const fn profile(&self) -> TranscriptSigningProfile {
        self.profile
    }

    /// Return the authenticated generation claim, pending verification.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the authenticated key claim, pending verification.
    #[must_use]
    pub const fn fingerprint(&self) -> KeyFingerprint {
        self.fingerprint
    }
}

impl fmt::Debug for IdentityTranscriptSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityTranscriptSignature")
            .field("profile", &self.profile)
            .field("generation", &self.generation)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// An opaque snapshot of one explicitly trusted public signing identity.
///
/// Import this from a trusted identity source, never from an untrusted
/// signature's claimed key. The caller supplies the independently trusted
/// active generation; revoked and retired records cannot be imported.
/// A detached snapshot cannot discover subsequent rotations or revocations.
/// Refresh it when trust changes, or use [`IdentityKeyStore::verify_transcript`]
/// to consult the current state of the loaded store on every verification.
#[derive(Debug, Clone)]
pub struct IdentityTranscriptVerificationKey {
    profile: TranscriptSigningProfile,
    identity: PublicIdentityKey,
}

impl IdentityTranscriptVerificationKey {
    /// Pin a canonical public User NKey and its active generation.
    ///
    /// Cryptographic verification retains the incumbent NKey primitive's
    /// semantics. Pin keys generated by an authoritative identity store;
    /// this is not a new strict Ed25519 public-key admission policy.
    pub fn from_public_identity(
        profile: TranscriptSigningProfile,
        identity: &PublicIdentityKey,
        active_generation: u64,
    ) -> Result<Self, IdentityTranscriptError> {
        if identity.generation == 0 || active_generation == 0 {
            return Err(IdentityTranscriptError::InvalidGeneration);
        }
        if identity.revoked {
            return Err(IdentityTranscriptError::Revoked);
        }
        if identity.generation != active_generation {
            return Err(IdentityTranscriptError::InactiveGeneration);
        }
        if identity.public_key.len() != 56 {
            return Err(IdentityTranscriptError::PublicKey);
        }
        let key = KeyPair::from_public_key(&identity.public_key)
            .map_err(|_| IdentityTranscriptError::PublicKey)?;
        if key.key_pair_type() != KeyPairType::User || key.public_key() != identity.public_key {
            return Err(IdentityTranscriptError::PublicKey);
        }
        let fingerprint = KeyFingerprint::from_public_key(identity.public_key.as_bytes())
            .map_err(|_| IdentityTranscriptError::PublicKey)?;
        if fingerprint != identity.fingerprint {
            return Err(IdentityTranscriptError::FingerprintMismatch);
        }
        Ok(Self {
            profile,
            identity: identity.clone(),
        })
    }

    /// Return the non-secret identity snapshot that was pinned.
    #[must_use]
    pub fn public_identity(&self) -> &PublicIdentityKey {
        &self.identity
    }

    /// Verify the exact domain and transcript against this pinned identity.
    ///
    /// No JSON, text, or application-level canonicalization is performed.
    /// Authentication does not imply authorization or replay protection.
    pub fn verify_transcript(
        &self,
        domain: &[u8],
        transcript: &[u8],
        signature: &IdentityTranscriptSignature,
    ) -> Result<(), IdentityTranscriptError> {
        if signature.profile != self.profile {
            return Err(IdentityTranscriptError::ProfileMismatch);
        }
        if signature.generation != self.identity.generation
            || signature.fingerprint != self.identity.fingerprint
        {
            return Err(IdentityTranscriptError::IdentityMismatch);
        }
        let digest = identity_transcript_digest(
            self.profile,
            self.identity.generation,
            self.identity.fingerprint,
            domain,
            transcript,
        )?;
        KeyPair::from_public_key(&self.identity.public_key)
            .map_err(|_| IdentityTranscriptError::PublicKey)?
            .verify(&digest, &signature.signature)
            .map_err(|_| IdentityTranscriptError::Verification)
    }
}

fn identity_transcript_digest(
    profile: TranscriptSigningProfile,
    generation: u64,
    fingerprint: KeyFingerprint,
    domain: &[u8],
    transcript: &[u8],
) -> Result<[u8; 32], IdentityTranscriptError> {
    if domain.is_empty() || domain.len() > MAX_TRANSCRIPT_DOMAIN_BYTES {
        return Err(IdentityTranscriptError::Domain);
    }
    let domain_len = u8::try_from(domain.len()).map_err(|_| IdentityTranscriptError::Domain)?;
    let transcript_len =
        u64::try_from(transcript.len()).map_err(|_| IdentityTranscriptError::TranscriptLength)?;
    let mut digest = Sha256::new();
    digest.update(IDENTITY_TRANSCRIPT_DOMAIN);
    digest.update([profile.wire_id()]);
    digest.update(generation.to_be_bytes());
    digest.update(fingerprint.as_bytes());
    digest.update([domain_len]);
    digest.update(domain);
    digest.update(transcript_len.to_be_bytes());
    digest.update(transcript);
    Ok(digest.finalize().into())
}

/// Platform-specific key-file hardening strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStorePlatform {
    /// Unix-like hosts use owner-only `0600` key files.
    UnixOwnerOnly,
    /// Windows hosts require ACL hardening by the daemon installer.
    WindowsAclRequired,
    /// Other targets persist records with best-effort process ownership.
    BestEffort,
}

impl KeyStorePlatform {
    /// Return the strategy for the current compilation target.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(unix) {
            Self::UnixOwnerOnly
        } else if cfg!(windows) {
            Self::WindowsAclRequired
        } else {
            Self::BestEffort
        }
    }
}

/// Filesystem-backed ATP identity key store.
#[derive(Debug, Clone)]
pub struct IdentityKeyStore {
    path: PathBuf,
    record: KeyStoreRecord,
}

impl IdentityKeyStore {
    /// Create a new store with an initial active key.
    pub fn create(
        path: impl AsRef<Path>,
        seed_material: [u8; 32],
        created_at_micros: u64,
    ) -> Result<Self, KeyStoreError> {
        let path = path.as_ref().to_path_buf();
        if path.try_exists().map_err(|source| KeyStoreError::Io {
            path: path.clone(),
            source,
        })? {
            return Err(KeyStoreError::StoreAlreadyExists(path));
        }

        let record = KeyStoreRecord {
            schema_version: KEY_STORE_SCHEMA_VERSION,
            active_generation: 1,
            next_generation: 2,
            keys: vec![persisted_key(seed_material, 1, created_at_micros)?],
        };
        persist_record(&path, &record)?;
        Ok(Self { path, record })
    }

    /// Load an existing key store from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, KeyStoreError> {
        let path = path.as_ref().to_path_buf();
        let text = fs::read_to_string(&path).map_err(|source| KeyStoreError::Io {
            path: path.clone(),
            source,
        })?;
        let record: KeyStoreRecord =
            serde_json::from_str(&text).map_err(|source| KeyStoreError::Json {
                path: path.clone(),
                source,
            })?;
        validate_record(&record)?;
        Ok(Self { path, record })
    }

    /// Return the backing store path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the platform hardening strategy used by this store.
    #[must_use]
    pub fn platform(&self) -> KeyStorePlatform {
        KeyStorePlatform::current()
    }

    /// Return the active generation number.
    #[must_use]
    pub const fn active_generation(&self) -> u64 {
        self.record.active_generation
    }

    /// Export the active public identity key.
    pub fn export_public(&self) -> Result<PublicIdentityKey, KeyStoreError> {
        let active = self.active_key_record()?;
        active.public_view()
    }

    /// Export every public key generation in deterministic order.
    pub fn export_public_history(&self) -> Result<Vec<PublicIdentityKey>, KeyStoreError> {
        self.record
            .keys
            .iter()
            .map(PersistedIdentityKey::public_view)
            .collect()
    }

    /// Return the active NKey key pair for signing.
    pub fn active_key_pair(&self) -> Result<KeyPair, KeyStoreError> {
        self.key_pair_for(self.active_key_record()?)
    }

    /// Export an opaque verifier for the active identity and explicit profile.
    ///
    /// This contains only public material. It is a snapshot: another store
    /// instance or clone can rotate independently, so applications must reload
    /// their store and refresh exported verifiers when authoritative trust
    /// changes. No disk access or ambient time is used by this operation.
    pub fn transcript_verification_key(
        &self,
        profile: TranscriptSigningProfile,
    ) -> Result<IdentityTranscriptVerificationKey, IdentityTranscriptError> {
        let identity = self
            .export_public()
            .map_err(|_| IdentityTranscriptError::KeyUnavailable)?;
        IdentityTranscriptVerificationKey::from_public_identity(
            profile,
            &identity,
            self.record.active_generation,
        )
    }

    /// Sign exact caller-supplied canonical bytes under an application domain.
    ///
    /// The profile signs the SHA-256 digest of this unambiguous byte sequence:
    /// ASUPERSYNC-IDENTITY-TRANSCRIPT-V1\0, profile (u8), generation
    /// (u64 big-endian), fingerprint (32 bytes), domain length (u8), domain,
    /// transcript length (u64 big-endian), transcript. Domains must contain
    /// 1 to 255 bytes. Empty transcripts are allowed. Hashing borrows the input
    /// and does not allocate a second transcript-sized buffer.
    ///
    /// The active public identity and signing key come from the same immutable
    /// store record. The existing NKey primitive signs the digest; no secret
    /// material or external key type crosses this API. Secret erasure retains
    /// the existing store/primitive guarantees; this does not erase the legacy
    /// persisted seed, store clones, or caller-created copies.
    pub fn sign_transcript(
        &self,
        profile: TranscriptSigningProfile,
        domain: &[u8],
        transcript: &[u8],
    ) -> Result<IdentityTranscriptSignature, IdentityTranscriptError> {
        let active = self
            .active_key_record()
            .map_err(|_| IdentityTranscriptError::KeyUnavailable)?;
        let identity = active
            .public_view()
            .map_err(|_| IdentityTranscriptError::KeyUnavailable)?;
        let digest = identity_transcript_digest(
            profile,
            identity.generation,
            identity.fingerprint,
            domain,
            transcript,
        )?;
        let key = self
            .key_pair_for(active)
            .map_err(|_| IdentityTranscriptError::KeyUnavailable)?;
        let signature = key
            .sign(&digest)
            .map_err(|_| IdentityTranscriptError::Signing)?
            .try_into()
            .map_err(|_| IdentityTranscriptError::Signing)?;
        Ok(IdentityTranscriptSignature {
            profile,
            generation: identity.generation,
            fingerprint: identity.fingerprint,
            signature,
        })
    }

    /// Verify using the active generation of this loaded store.
    ///
    /// Retired, unknown and revoked generations fail before cryptographic
    /// verification. Unlike a detached verifier, this observes rotations and
    /// revocations performed through this instance. Independently loaded or
    /// cloned stores retain snapshots and must be refreshed by the caller.
    pub fn verify_transcript(
        &self,
        domain: &[u8],
        transcript: &[u8],
        signature: &IdentityTranscriptSignature,
    ) -> Result<(), IdentityTranscriptError> {
        let key = self
            .record
            .keys
            .iter()
            .find(|key| key.generation == signature.generation)
            .ok_or(IdentityTranscriptError::InactiveGeneration)?;
        if key.revoked {
            return Err(IdentityTranscriptError::Revoked);
        }
        if key.generation != self.record.active_generation {
            return Err(IdentityTranscriptError::InactiveGeneration);
        }
        self.transcript_verification_key(signature.profile)?
            .verify_transcript(domain, transcript, signature)
    }

    /// Rotate to a new active key generation.
    pub fn rotate(
        &mut self,
        seed_material: [u8; 32],
        created_at_micros: u64,
    ) -> Result<PublicIdentityKey, KeyStoreError> {
        let generation = self.record.next_generation;
        let key = persisted_key(seed_material, generation, created_at_micros)?;
        let fingerprint = KeyFingerprint::from_hex(&key.fingerprint)?;
        if self
            .record
            .keys
            .iter()
            .any(|existing| existing.fingerprint == key.fingerprint)
        {
            return Err(KeyStoreError::DuplicateFingerprint(fingerprint));
        }

        let next_generation = generation
            .checked_add(1)
            .ok_or(KeyStoreError::GenerationOverflow)?;
        let previous_active = self.record.active_generation;
        self.record.active_generation = generation;
        self.record.next_generation = next_generation;
        self.record.keys.push(key);
        if let Err(err) =
            validate_record(&self.record).and_then(|()| persist_record(&self.path, &self.record))
        {
            // The store on disk did not change, so memory must not either:
            // signing with a key the store cannot reload would strand every
            // token it signs.
            self.record.keys.pop();
            self.record.active_generation = previous_active;
            self.record.next_generation = generation;
            return Err(err);
        }
        self.export_public()
    }

    /// Revoke a non-active key by fingerprint.
    pub fn revoke(
        &mut self,
        fingerprint: KeyFingerprint,
        revoked_at_micros: u64,
    ) -> Result<PublicIdentityKey, KeyStoreError> {
        let fingerprint_hex = fingerprint.to_hex();
        let Some(index) = self
            .record
            .keys
            .iter()
            .position(|key| key.fingerprint == fingerprint_hex)
        else {
            return Err(KeyStoreError::UnknownFingerprint(fingerprint));
        };
        if self.record.keys[index].generation == self.record.active_generation {
            return Err(KeyStoreError::CannotRevokeActiveKey(fingerprint));
        }
        let key = &mut self.record.keys[index];
        let previous = (key.revoked, key.revoked_at_micros);
        key.revoked = true;
        key.revoked_at_micros = Some(revoked_at_micros);
        let revoked = self.record.keys[index].public_view().and_then(|revoked| {
            validate_record(&self.record)?;
            persist_record(&self.path, &self.record)?;
            Ok(revoked)
        });
        if revoked.is_err() {
            // Not persisted: a key that is revoked only in memory would be
            // valid again after a restart, so keep memory equal to disk.
            let key = &mut self.record.keys[index];
            (key.revoked, key.revoked_at_micros) = previous;
        }
        revoked
    }

    fn active_key_record(&self) -> Result<&PersistedIdentityKey, KeyStoreError> {
        let active = self
            .record
            .keys
            .iter()
            .find(|key| key.generation == self.record.active_generation)
            .ok_or(KeyStoreError::NoActiveKey)?;
        if active.revoked {
            return Err(KeyStoreError::ActiveKeyRevoked);
        }
        Ok(active)
    }

    fn key_pair_for(&self, key: &PersistedIdentityKey) -> Result<KeyPair, KeyStoreError> {
        let key_pair = KeyPair::from_seed(&key.seed).map_err(|err| {
            KeyStoreError::InvalidSeed(format!(
                "generation {} seed could not be decoded: {err}",
                key.generation
            ))
        })?;
        if key_pair.key_pair_type() != KeyPairType::User {
            return Err(KeyStoreError::InvalidSeed(format!(
                "generation {} is {:?}, expected User",
                key.generation,
                key_pair.key_pair_type()
            )));
        }
        if key_pair.public_key() != key.public_key {
            return Err(KeyStoreError::PublicKeyMismatch {
                generation: key.generation,
            });
        }
        Ok(key_pair)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyStoreRecord {
    schema_version: u32,
    active_generation: u64,
    next_generation: u64,
    keys: Vec<PersistedIdentityKey>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedIdentityKey {
    generation: u64,
    public_key: String,
    seed: String,
    fingerprint: String,
    created_at_micros: u64,
    revoked: bool,
    revoked_at_micros: Option<u64>,
}

impl fmt::Debug for PersistedIdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedIdentityKey")
            .field("generation", &self.generation)
            .field("public_key", &self.public_key)
            .field("seed", &"<redacted>")
            .field("fingerprint", &self.fingerprint)
            .field("created_at_micros", &self.created_at_micros)
            .field("revoked", &self.revoked)
            .field("revoked_at_micros", &self.revoked_at_micros)
            .finish()
    }
}

impl PersistedIdentityKey {
    fn public_view(&self) -> Result<PublicIdentityKey, KeyStoreError> {
        Ok(PublicIdentityKey {
            generation: self.generation,
            public_key: self.public_key.clone(),
            fingerprint: KeyFingerprint::from_hex(&self.fingerprint)?,
            revoked: self.revoked,
        })
    }
}

/// Durable key-store failures.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// Filesystem operation failed.
    #[error("key store I/O failed for {}: {source}", path.display())]
    Io {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// JSON parsing or serialization failed.
    #[error("key store JSON failed for {}: {source}", path.display())]
    Json {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },
    /// Store creation would overwrite an existing record.
    #[error("key store already exists: {}", .0.display())]
    StoreAlreadyExists(PathBuf),
    /// Store path has no valid file name.
    #[error("invalid key store path: {}", .0.display())]
    InvalidStorePath(PathBuf),
    /// Persistent schema version is unsupported.
    #[error("unsupported key store schema version: {0}")]
    UnsupportedSchema(u32),
    /// Store contains no key generations.
    #[error("key store contains no key generations")]
    EmptyStore,
    /// Store has no usable active key.
    #[error("key store has no active key")]
    NoActiveKey,
    /// Active key was marked revoked.
    #[error("active key generation is revoked")]
    ActiveKeyRevoked,
    /// Active key cannot be revoked before rotation.
    #[error("cannot revoke active key {0}")]
    CannotRevokeActiveKey(KeyFingerprint),
    /// Requested fingerprint is not present.
    #[error("unknown key fingerprint: {0}")]
    UnknownFingerprint(KeyFingerprint),
    /// Rotation would reuse an existing key.
    #[error("duplicate key fingerprint: {0}")]
    DuplicateFingerprint(KeyFingerprint),
    /// Generation counter overflowed.
    #[error("key generation overflow")]
    GenerationOverflow,
    /// Caller-provided seed material was weak.
    #[error("weak identity seed: {0}")]
    WeakSeed(&'static str),
    /// Encoded seed was invalid.
    #[error("invalid identity seed: {0}")]
    InvalidSeed(String),
    /// Public key material was invalid.
    #[error("invalid public identity key: {0}")]
    InvalidPublicKey(String),
    /// Fingerprint encoding was invalid.
    #[error("invalid key fingerprint: {0}")]
    InvalidFingerprint(String),
    /// Stored public key did not match the stored seed.
    #[error("stored public key does not match seed for generation {generation}")]
    PublicKeyMismatch {
        /// Generation that failed validation.
        generation: u64,
    },
    /// Stored fingerprint did not match the public key.
    #[error("stored fingerprint does not match public key for generation {generation}")]
    FingerprintMismatch {
        /// Generation that failed validation.
        generation: u64,
    },
    /// Store has duplicate generations or fingerprints.
    #[error("duplicate key-store field: {0}")]
    DuplicateRecordField(&'static str),
}

fn persisted_key(
    seed_material: [u8; 32],
    generation: u64,
    created_at_micros: u64,
) -> Result<PersistedIdentityKey, KeyStoreError> {
    validate_seed_material(&seed_material)?;
    let key_pair = KeyPair::new_from_raw(KeyPairType::User, seed_material)
        .map_err(|err| KeyStoreError::InvalidSeed(err.to_string()))?;
    let seed = key_pair
        .seed()
        .map_err(|err| KeyStoreError::InvalidSeed(err.to_string()))?;
    let public_key = key_pair.public_key();
    validate_public_key(&public_key, generation)?;
    let fingerprint = KeyFingerprint::from_public_key(public_key.as_bytes())?.to_hex();

    Ok(PersistedIdentityKey {
        generation,
        public_key,
        seed,
        fingerprint,
        created_at_micros,
        revoked: false,
        revoked_at_micros: None,
    })
}

fn validate_seed_material(seed: &[u8; 32]) -> Result<(), KeyStoreError> {
    if seed.iter().all(|byte| *byte == 0) {
        return Err(KeyStoreError::WeakSeed("all-zero seed"));
    }

    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &byte in seed {
        let idx = byte as usize;
        if !seen[idx] {
            seen[idx] = true;
            distinct += 1;
        }
    }
    if distinct < MIN_SEED_DISTINCT_BYTES {
        return Err(KeyStoreError::WeakSeed("insufficient byte diversity"));
    }

    let hamming_weight: u32 = seed.iter().map(|byte| byte.count_ones()).sum();
    if !(MIN_SEED_HAMMING_WEIGHT..=MAX_SEED_HAMMING_WEIGHT).contains(&hamming_weight) {
        return Err(KeyStoreError::WeakSeed("extreme hamming weight"));
    }

    Ok(())
}

fn validate_record(record: &KeyStoreRecord) -> Result<(), KeyStoreError> {
    if record.schema_version != KEY_STORE_SCHEMA_VERSION {
        return Err(KeyStoreError::UnsupportedSchema(record.schema_version));
    }
    if record.keys.is_empty() {
        return Err(KeyStoreError::EmptyStore);
    }
    if record.next_generation <= record.active_generation {
        return Err(KeyStoreError::GenerationOverflow);
    }

    let mut generations = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut has_active = false;
    for key in &record.keys {
        if !generations.insert(key.generation) {
            return Err(KeyStoreError::DuplicateRecordField("generation"));
        }
        if !fingerprints.insert(key.fingerprint.clone()) {
            return Err(KeyStoreError::DuplicateRecordField("fingerprint"));
        }
        validate_public_key(&key.public_key, key.generation)?;
        let fingerprint = KeyFingerprint::from_public_key(key.public_key.as_bytes())?;
        if key.fingerprint != fingerprint.to_hex() {
            return Err(KeyStoreError::FingerprintMismatch {
                generation: key.generation,
            });
        }
        if key.generation == record.active_generation {
            has_active = true;
            if key.revoked {
                return Err(KeyStoreError::ActiveKeyRevoked);
            }
        }
        let key_pair = KeyPair::from_seed(&key.seed).map_err(|err| {
            KeyStoreError::InvalidSeed(format!(
                "generation {} seed could not be decoded: {err}",
                key.generation
            ))
        })?;
        if key_pair.key_pair_type() != KeyPairType::User {
            return Err(KeyStoreError::InvalidSeed(format!(
                "generation {} is {:?}, expected User",
                key.generation,
                key_pair.key_pair_type()
            )));
        }
        if key_pair.public_key() != key.public_key {
            return Err(KeyStoreError::PublicKeyMismatch {
                generation: key.generation,
            });
        }
    }

    if has_active {
        Ok(())
    } else {
        Err(KeyStoreError::NoActiveKey)
    }
}

fn validate_public_key(public_key: &str, generation: u64) -> Result<(), KeyStoreError> {
    KeyPair::from_public_key(public_key).map_err(|err| {
        KeyStoreError::InvalidPublicKey(format!(
            "generation {generation} public key could not be decoded: {err}"
        ))
    })?;
    KeyFingerprint::from_public_key(public_key.as_bytes())?;
    Ok(())
}

fn persist_record(path: &Path, record: &KeyStoreRecord) -> Result<(), KeyStoreError> {
    let parent = path.parent();
    if let Some(parent) = parent {
        fs::create_dir_all(parent).map_err(|source| KeyStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let tmp_path = pending_path(path)?;
    let mut bytes = serde_json::to_vec_pretty(record).map_err(|source| KeyStoreError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    // The serialized record holds every key seed: wipe it once written.
    let written = write_key_file(&tmp_path, &bytes);
    bytes.zeroize();
    written?;
    fs::rename(&tmp_path, path).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    harden_key_file(path)?;
    sync_parent_dir(parent);
    Ok(())
}

fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), KeyStoreError> {
    let mut options = OpenOptions::new();
    // The pending path is security-sensitive. Exclusive creation prevents
    // following an attacker-controlled stale symlink or truncating a real file.
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(bytes).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(b"\n").map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    harden_key_file(path)
}

fn pending_path(path: &Path) -> Result<PathBuf, KeyStoreError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| KeyStoreError::InvalidStorePath(path.to_path_buf()))?;
    let mut pending_name = file_name.to_os_string();
    pending_name.push(".pending");
    Ok(path.with_file_name(pending_name))
}

fn harden_key_file(path: &Path) -> Result<(), KeyStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions).map_err(|source| KeyStoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sync_parent_dir(parent: Option<&Path>) {
    if let Some(parent) = parent {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

#[cfg(test)]
#[path = "mod_inline_tests.rs"]
mod tests;
