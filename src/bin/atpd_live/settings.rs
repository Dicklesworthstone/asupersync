//! Strict, explicitly provisioned settings for the foreground live profile.

use asupersync::net::atp::sdk::native_auth::live::{LiveStreamConfig, MAX_LIVE_EPOCH_BYTES};
use asupersync::net::atp::sdk::{AtpSdk, NativeClientCertificateId, NativeTlsIdentity, SessionConfig};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
const MAX_PEM_BYTES: u64 = 256 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IdentityFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InboxConfig {
    pub certificate_sha256: String,
    pub directory: PathBuf,
    /// Logical bytes counted per directory entry, including retained aliases.
    pub max_retained_bytes: u64,
    pub max_retained_entries: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServeConfig {
    pub schema_version: u32,
    pub bind: SocketAddr,
    pub identity: IdentityFiles,
    pub client_ca: PathBuf,
    pub clients: Vec<InboxConfig>,
    pub max_connections: u32,
    pub workers: usize,
    pub epoch_bytes: usize,
    pub max_transfer_bytes: u64,
    pub operation_timeout_secs: u64,
    pub shutdown_grace_secs: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SendConfig {
    pub schema_version: u32,
    pub remote: SocketAddr,
    pub server_name: String,
    pub server_ca: PathBuf,
    pub identity: IdentityFiles,
    pub workers: usize,
    pub epoch_bytes: usize,
    pub max_transfer_bytes: u64,
    pub operation_timeout_secs: u64,
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Reject symlinks and special files before reading; NONBLOCK prevents FIFO open.
/// Parents/ACLs remain caller-trusted. No file is created or changed here.
pub(super) fn open_regular(path: &Path, private: bool) -> io::Result<File> {
    let file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("a regular, non-symlink file is required"));
    }
    if private && metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "private key must deny group and other permissions"));
    }
    Ok(file)
}

fn read_bounded(path: &Path, limit: u64, private: bool) -> io::Result<Zeroizing<Vec<u8>>> {
    let file = open_regular(path, private)?;
    if file.metadata()?.len() > limit { return Err(invalid("configuration input too large")); }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(invalid("configuration input grew beyond its limit")); }
    Ok(bytes)
}

pub(super) fn load<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let bytes = read_bounded(path, MAX_SETTINGS_BYTES, false)?;
    // Do not echo arbitrary config values, input fragments or secret contents.
    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid atpd-live JSON settings"))
}

fn certificates(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let bytes = read_bounded(path, MAX_PEM_BYTES, false)?;
    let mut reader = io::BufReader::new(bytes.as_slice());
    let mut result = Vec::new();
    for certificate in CertificateDer::pem_reader_iter(&mut reader) {
        if result.len() == 128 { return Err(invalid("too many certificates")); }
        result.push(certificate.map_err(|_| invalid("invalid certificate PEM"))?);
    }
    if result.is_empty() { return Err(invalid("no certificates in PEM file")); }
    Ok(result)
}

pub(super) fn identity(files: &IdentityFiles) -> io::Result<NativeTlsIdentity> {
    let chain = certificates(&files.certificate)?;
    if chain.len() > 32 { return Err(invalid("identity chain too long")); }
    let bytes = read_bounded(&files.private_key, MAX_PEM_BYTES, true)?;
    let mut reader = io::BufReader::new(bytes.as_slice());
    let mut keys = PrivateKeyDer::pem_reader_iter(&mut reader);
    let key = keys.next().transpose().map_err(|_| invalid("invalid private key PEM"))?
        .ok_or_else(|| invalid("private key PEM is empty"))?;
    if keys.next().is_some() { return Err(invalid("exactly one private key is required")); }
    NativeTlsIdentity::new(chain, key).map_err(|_| invalid("invalid TLS identity"))
}

pub(super) fn roots(path: &Path) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(path)? {
        roots.add(certificate).map_err(|_| invalid("invalid explicit CA certificate"))?;
    }
    Ok(roots)
}

pub(super) fn selector(text: &str) -> io::Result<NativeClientCertificateId> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("client certificate selector must be 64 hexadecimal characters"));
    }
    let mut bytes = [0; 32];
    for (out, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let digit = |byte: u8| if byte.is_ascii_digit() { byte - b'0' } else { byte.to_ascii_lowercase() - b'a' + 10 };
        *out = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(NativeClientCertificateId::from_sha256(bytes))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}

pub(super) fn profile(version: u32, workers: usize, epoch: usize, bytes: u64, timeout: u64)
    -> io::Result<LiveStreamConfig>
{
    if version != 1 || !(1..=32).contains(&workers) || !(1..=MAX_LIVE_EPOCH_BYTES).contains(&epoch)
        || !(1..=86400).contains(&timeout) || bytes > u64::MAX / 2
    {
        return Err(invalid("unsupported schema or invalid runtime/transfer limits"));
    }
    let mut config = LiveStreamConfig::default();
    config.epoch_bytes = epoch;
    config.max_bytes = bytes;
    config.operation_timeout = Duration::from_secs(timeout);
    Ok(config)
}

pub(super) fn sdk(connections: u32, config: &LiveStreamConfig) -> io::Result<AtpSdk> {
    if !(1..=1024).contains(&connections) { return Err(invalid("connection limit must be 1..=1024")); }
    let sdk = AtpSdk::new_in_process(SessionConfig {
        max_concurrent_transfers: connections, ..SessionConfig::default()
    });
    let mut policy = sdk.transfer_policy().clone();
    policy.max_transfer_size_bytes = config.max_bytes;
    policy.max_chunk_size_bytes = config.epoch_bytes.try_into()
        .map_err(|_| invalid("epoch limit is not representable"))?;
    Ok(sdk.with_transfer_policy(policy))
}
