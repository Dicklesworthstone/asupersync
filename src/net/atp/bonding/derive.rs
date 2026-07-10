//! Library helper that derives the agreed [`BondTransferDescriptor`] from a
//! local, byte-identical copy of the transfer content.
//!
//! The bonded enrollment protocol never transmits the descriptor: every donor
//! and the receiver derive it independently from their own bytes and fail
//! closed on any transfer-id / merkle-root / metadata mismatch. This helper is
//! that single derivation, shared by the `atp` CLI (`bond-recv`,
//! `bond-donate`, `bond-descriptor`) and the net SDK ([`BondedTransfer`]), so
//! there is exactly one implementation of "local bytes -> descriptor".
//!
//! [`BondedTransfer`]: crate::net::atp::sdk::BondedTransfer

use std::path::Path;

use crate::atp::object::MetadataPolicy;
use crate::cx::Cx;
use crate::net::atp::channel_bonding::transfer_id_hex;
use crate::net::atp::transport_common::plan_transfer;
use crate::net::atp::transport_rq::{
    ManifestEntry, RqConfig, RqError, TransferManifest, source_metadata_manifest_with_config,
};
use crate::net::atp::transport_tcp::DEFAULT_CHUNK_SIZE;

use super::BondTransferDescriptor;

/// Derive the shared bonded descriptor from a local byte-identical copy.
///
/// Donors can legitimately run on different operating systems. Platform modes,
/// attributes, ownership, and timestamps are not byte identity and would make
/// identical content derive different enrollment descriptors, so this commits
/// only the portable content/path shape ([`MetadataPolicy::portable`]) while
/// keeping topology checks (including hardlink rejection). The per-entry
/// SHA-256 digests and flat-graph merkle root come from [`plan_transfer`]; the
/// transfer id is the RaptorQ derivation ([`transfer_id_hex`]); the agreed
/// RaptorQ object params (`symbol_size`, `max_block_size`) and the optional
/// shared-key id (`auth_key_id`) are the params every participant must match.
///
/// The chunk size used for the plan pass is [`DEFAULT_CHUNK_SIZE`], the exact
/// value the CLI's `tcp_config(max_bytes, false).chunk_size` produces (it does
/// not depend on `max_bytes`).
///
/// # Errors
///
/// Returns [`RqError::Source`] when the source cannot be walked/hashed or when
/// the derived descriptor fails its own self-consistency validation, and
/// [`RqError::TooLarge`] when the source exceeds `max_bytes`.
pub async fn derive_bonded_descriptor(
    cx: &Cx,
    source: &Path,
    symbol_size: u16,
    max_block_size: u64,
    max_bytes: u64,
    auth_key_id: Option<String>,
) -> Result<BondTransferDescriptor, RqError> {
    // Portable capture only: platform metadata is not byte identity and would
    // make identical content derive different enrollment descriptors. Bonded
    // transfers always preserve hardlink topology (the CLI's `rq_config`
    // posture), so a hardlink secondary is sent content-free identically here.
    let descriptor_config = RqConfig {
        symbol_size,
        // Clamp to >= symbol_size, mirroring the SDK/CLI `build_config` posture
        // so every caller derives a byte-identical enrollment descriptor even if
        // handed an unclamped max_block_size below the symbol size.
        max_block_size: usize::try_from(max_block_size)
            .unwrap_or(usize::MAX)
            .max(usize::from(symbol_size.max(1))),
        max_transfer_bytes: max_bytes,
        metadata_policy: MetadataPolicy::portable(),
        preserve_hardlinks: true,
        ..RqConfig::default()
    };
    let metadata = source_metadata_manifest_with_config(source, &descriptor_config).await?;
    let plan = plan_transfer(
        cx,
        source,
        DEFAULT_CHUNK_SIZE,
        &descriptor_config.metadata_policy,
        descriptor_config.preserve_hardlinks,
    )
    .await
    .map_err(|error| RqError::Source(format!("bond descriptor derivation: {error}")))?;
    if plan.total_bytes > max_bytes {
        return Err(RqError::TooLarge {
            size: plan.total_bytes,
            max: max_bytes,
        });
    }
    let entries: Vec<ManifestEntry> = plan
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            u32::try_from(index)
                .map(|index| ManifestEntry {
                    index,
                    rel_path: entry.rel_path.clone(),
                    size: entry.size,
                    sha256_hex: entry.sha256_hex.clone(),
                    members: Vec::new(),
                    fragment: None,
                })
                .map_err(|_| {
                    RqError::Source(format!(
                        "bond descriptor has too many entries: {}",
                        plan.entries.len()
                    ))
                })
        })
        .collect::<Result<_, _>>()?;
    let manifest = TransferManifest {
        transfer_id: transfer_id_hex(&plan.merkle_root_hex, plan.total_bytes, entries.len()),
        root_name: plan.root_name.clone(),
        is_directory: plan.is_directory,
        total_bytes: plan.total_bytes,
        merkle_root_hex: plan.merkle_root_hex.clone(),
        metadata: Some(metadata),
        entries,
    };
    let descriptor =
        BondTransferDescriptor::from_manifest(&manifest, symbol_size, max_block_size, auth_key_id);
    descriptor
        .validate()
        .map_err(|error| RqError::Source(format!("bond descriptor validation: {error}")))?;
    Ok(descriptor)
}
