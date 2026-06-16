//! RaptorQ-over-QUIC datagram loss recovery — end-to-end (`arq-quic-epic-b0k8qo.2.4`, "B4" slice).
//!
//! Proves the epic's headline data-plane property without the (still in-flight)
//! B2/B3 coroutines: a buffer is RaptorQ-encoded into source + repair symbols,
//! each symbol is sprayed over the QUIC DATAGRAM plane via the A6
//! [`QuicConnection`] + the `symbol_datagram` bridge, some **source** symbols are
//! "lost" in transit, and the surviving **K-of-N** symbols recover the original
//! buffer through the RaptorQ decoder — and, conversely, fewer than K symbols
//! fail to decode (fountain threshold, fail closed).
//!
//! It composes real RaptorQ (`EncodingPipeline` / `DecodingPipeline`) + the A6
//! deterministic loopback + the `Symbol`↔datagram bridge. Scope: public
//! data-plane proof, including single- and multi-source-block objects. The full
//! directory-tree / SHA-256 verify / atomic commit pipeline is B4 proper, driven
//! by the B2/B3 sender/receiver coroutines. Public API only.

#![allow(clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use asupersync::config::EncodingConfig;
use asupersync::cx::Cx;
use asupersync::decoding::{DecodingConfig, DecodingPipeline};
use asupersync::encoding::EncodingPipeline;
use asupersync::net::atp::sdk::object::{
    ManifestBuilder, ManifestEntry, ObjectHash, ObjectManifest, ObjectMetadata,
};
use asupersync::net::atp::transport_quic::{envelope_to_symbol, recv_symbol_envelope, send_symbol};
use asupersync::net::quic_native::{
    DEFAULT_MAX_PACKET_BYTES, NativeQuicConnectionConfig, QuicConnection, establish_loopback,
    pump_until_idle,
};
use asupersync::security::tag::AuthenticationTag;
use asupersync::security::{AuthenticatedSymbol, SecurityContext};
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolKind};
use sha2::{Digest, Sha256};

const SYMBOL_SIZE: u16 = 256;
const MAX_BLOCK_SIZE: usize = 8192;
/// 2048 / 256 = 8 source symbols in a single source block.
const DATA_LEN: usize = 2048;

fn test_cx() -> Cx {
    Cx::for_testing()
}

/// Byte-varied payload so erasure recovery is non-vacuous (a constant buffer
/// would let a wrong decode still "match").
fn make_data(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u64).wrapping_mul(31).wrapping_add(7) % 251) as u8)
        .collect()
}

fn make_seeded_data(len: usize, seed: u8) -> Vec<u8> {
    make_data(len)
        .into_iter()
        .enumerate()
        .map(|(i, b)| b ^ seed.wrapping_add((i % 251) as u8))
        .collect()
}

fn pool() -> SymbolPool {
    SymbolPool::new(PoolConfig::new(SYMBOL_SIZE, 64, 256, true, 64))
}

fn encoding_config() -> EncodingConfig {
    EncodingConfig {
        symbol_size: SYMBOL_SIZE,
        max_block_size: MAX_BLOCK_SIZE,
        repair_overhead: 1.0,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    }
}

fn decoding_config() -> DecodingConfig {
    DecodingConfig {
        symbol_size: SYMBOL_SIZE,
        max_block_size: MAX_BLOCK_SIZE,
        repair_overhead: 1.0,
        min_overhead: 0,
        max_buffered_symbols: 0,
        block_timeout: Duration::from_secs(30),
        verify_auth: false,
    }
}

fn established_pair(cx: &Cx) -> (QuicConnection, QuicConnection) {
    let cfg = NativeQuicConnectionConfig::default();
    let mut client = QuicConnection::client(cfg);
    let mut server = QuicConnection::server(cfg);
    client.record_verified_server_identity();
    establish_loopback(cx, &mut client, &mut server).expect("loopback establishes");
    (client, server)
}

/// RaptorQ-encode `data` for `object_id` into source + `repair_count` repair
/// symbols.
fn encode_symbols(object_id: ObjectId, data: &[u8], repair_count: usize) -> Vec<Symbol> {
    let mut encoder = EncodingPipeline::new(encoding_config(), pool());
    encoder
        .encode_with_repair(object_id, data, repair_count)
        .map(|res| res.expect("encode symbol").into_symbol())
        .collect()
}

fn object_params(object_id: ObjectId, data_len: usize) -> ObjectParams {
    let symbol_size = usize::from(SYMBOL_SIZE);
    let source_blocks = data_len.div_ceil(MAX_BLOCK_SIZE);
    let mut max_symbols_per_block = 0usize;
    for block in 0..source_blocks {
        let start = block * MAX_BLOCK_SIZE;
        let block_len = (data_len - start).min(MAX_BLOCK_SIZE);
        max_symbols_per_block = max_symbols_per_block.max(block_len.div_ceil(symbol_size));
    }
    ObjectParams::new(
        object_id,
        u64::try_from(data_len).expect("test payload length fits u64"),
        SYMBOL_SIZE,
        u16::try_from(source_blocks).expect("test source block count fits u16"),
        u16::try_from(max_symbols_per_block).expect("test K fits u16"),
    )
}

/// Spray `symbols` over the QUIC datagram plane (client → server) and collect the
/// symbols the server reassembles. `object_id` reconstructs each `SymbolId` — in
/// the real receiver the manifest resolves it from the envelope's
/// `transfer_tag`/`entry`.
fn spray_and_collect(
    cx: &Cx,
    client: &mut QuicConnection,
    server: &mut QuicConnection,
    symbols: &[Symbol],
    object_id: ObjectId,
) -> Vec<Symbol> {
    for s in symbols {
        send_symbol(cx, client, s, 1, 0, None).expect("send symbol");
    }
    pump_until_idle(cx, client, server, DEFAULT_MAX_PACKET_BYTES, 1_000).expect("pump");
    let mut received = Vec::new();
    while let Some(env) = recv_symbol_envelope(server, false).expect("decode envelope") {
        received.push(envelope_to_symbol(&env, object_id));
    }
    received
}

/// Spray signed `symbols` over the QUIC datagram plane and preserve their tags
/// for decoder-side authentication.
fn spray_and_collect_authenticated(
    cx: &Cx,
    client: &mut QuicConnection,
    server: &mut QuicConnection,
    symbols: &[Symbol],
    object_id: ObjectId,
    signer: &SecurityContext,
) -> Vec<AuthenticatedSymbol> {
    for s in symbols {
        let signed = signer.sign_symbol(s);
        send_symbol(cx, client, s, 1, 0, Some(*signed.tag().as_bytes()))
            .expect("send signed symbol");
    }
    pump_until_idle(cx, client, server, DEFAULT_MAX_PACKET_BYTES, 1_000).expect("pump");
    let mut received = Vec::new();
    while let Some(env) = recv_symbol_envelope(server, true).expect("decode authed envelope") {
        let tag = env.auth_tag.expect("authenticated envelope carries a tag");
        let symbol = envelope_to_symbol(&env, object_id);
        received.push(AuthenticatedSymbol::from_parts(
            symbol,
            AuthenticationTag::from_bytes(tag),
        ));
    }
    received
}

/// Feed `symbols` into a fresh RaptorQ decoder for the object and attempt to
/// recover the original bytes.
fn recover_object(object_id: ObjectId, data_len: usize, symbols: &[Symbol]) -> Result<Vec<u8>, ()> {
    let params = object_params(object_id, data_len);
    let mut pipeline = DecodingPipeline::new(decoding_config());
    pipeline.set_object_params(params).expect("set params");
    for s in symbols {
        let auth = AuthenticatedSymbol::from_parts(s.clone(), AuthenticationTag::zero());
        let _ = pipeline.feed(auth).expect("feed symbol");
    }
    pipeline.into_data().map_err(|_| ())
}

/// Recover authenticated symbols with a receiver-held security context.
fn recover_object_authenticated(
    object_id: ObjectId,
    data_len: usize,
    symbols: &[AuthenticatedSymbol],
    verifier: SecurityContext,
) -> Result<Vec<u8>, ()> {
    let params = object_params(object_id, data_len);
    let mut config = decoding_config();
    config.verify_auth = true;
    let mut pipeline = DecodingPipeline::with_auth(config, verifier);
    pipeline.set_object_params(params).expect("set params");
    for s in symbols {
        let _ = pipeline.feed(s.clone()).map_err(|_| ())?;
    }
    pipeline.into_data().map_err(|_| ())
}

#[derive(Debug)]
struct TreeFixtureEntry {
    object_id: ObjectId,
    path: &'static str,
    content_type: &'static str,
    data: Vec<u8>,
    hash: ObjectHash,
}

impl TreeFixtureEntry {
    fn new(
        object_id: ObjectId,
        path: &'static str,
        content_type: &'static str,
        data: Vec<u8>,
    ) -> Self {
        let hash = ObjectHash::from_data(&data);
        Self {
            object_id,
            path,
            content_type,
            data,
            hash,
        }
    }
}

fn tree_fixture() -> Vec<TreeFixtureEntry> {
    vec![
        TreeFixtureEntry::new(
            ObjectId::from_u128(0xD0_01),
            "docs/readme.txt",
            "text/plain",
            make_seeded_data(DATA_LEN / 2, 0x11),
        ),
        TreeFixtureEntry::new(
            ObjectId::from_u128(0xD0_02),
            "bin/payload.dat",
            "application/octet-stream",
            make_seeded_data(MAX_BLOCK_SIZE + usize::from(SYMBOL_SIZE) * 3, 0x27),
        ),
        TreeFixtureEntry::new(
            ObjectId::from_u128(0xD0_03),
            "nested/deep/config.json",
            "application/json",
            br#"{"mode":"b4","transport":"quic","commit":"atomic"}"#.to_vec(),
        ),
    ]
}

fn tree_root_hash(entries: &[TreeFixtureEntry]) -> ObjectHash {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.tests.atp_quic_tree_manifest.v1");
    for entry in entries {
        hasher.update(entry.path.as_bytes());
        hasher.update([0]);
        hasher.update(entry.hash.as_bytes());
        hasher.update(
            u64::try_from(entry.data.len())
                .expect("fixture length fits u64")
                .to_le_bytes(),
        );
    }
    ObjectHash::new(hasher.finalize().into())
}

fn tree_manifest(entries: &[TreeFixtureEntry]) -> ObjectManifest {
    let mut builder = ManifestBuilder::new();
    for entry in entries {
        builder.add_object(
            entry.hash.clone(),
            entry.path.to_string(),
            u64::try_from(entry.data.len()).expect("fixture length fits u64"),
            entry.content_type.to_string(),
            ObjectMetadata::with_filename(entry.path),
        );
    }
    builder.add_metadata("shape".to_string(), "directory-tree".to_string());
    builder.build(tree_root_hash(entries))
}

fn drop_one_source_symbol_per_block(symbols: &[Symbol]) -> Vec<Symbol> {
    let mut dropped_by_block = BTreeMap::new();
    let mut sent = Vec::new();
    for symbol in symbols {
        if matches!(symbol.kind(), SymbolKind::Source) {
            let dropped = dropped_by_block.entry(symbol.sbn()).or_insert(0usize);
            if *dropped == 0 {
                *dropped += 1;
                continue;
            }
        }
        sent.push(symbol.clone());
    }
    assert!(
        !dropped_by_block.is_empty(),
        "fixture must drop at least one source symbol"
    );
    sent
}

fn recover_tree_entry_over_quic(
    cx: &Cx,
    client: &mut QuicConnection,
    server: &mut QuicConnection,
    entry: &TreeFixtureEntry,
) -> Vec<u8> {
    let symbols = encode_symbols(entry.object_id, &entry.data, 8);
    let sent = drop_one_source_symbol_per_block(&symbols);
    let datagrams_before = server.datagrams_received();

    let received = spray_and_collect(cx, client, server, &sent, entry.object_id);

    assert_eq!(received.len(), sent.len());
    assert_eq!(
        server.datagrams_received() - datagrams_before,
        sent.len() as u64
    );
    recover_object(entry.object_id, entry.data.len(), &received)
        .expect("tree entry recovers after per-block source loss")
}

fn destination_path(root: &Path, manifest_path: &str) -> PathBuf {
    let rel = Path::new(manifest_path);
    assert!(!rel.is_absolute(), "manifest paths must be relative");
    assert!(
        !rel.components()
            .any(|component| matches!(component, std::path::Component::ParentDir)),
        "manifest paths must not escape the destination root"
    );
    root.join(rel)
}

fn verify_and_commit_entry(
    root: &Path,
    manifest_entry: &ManifestEntry,
    decoded: &[u8],
) -> Result<PathBuf, String> {
    if ObjectHash::from_data(decoded) != manifest_entry.hash {
        return Err(format!("hash mismatch for {}", manifest_entry.path));
    }
    if decoded.len() as u64 != manifest_entry.size_bytes {
        return Err(format!("size mismatch for {}", manifest_entry.path));
    }

    let final_path = destination_path(root, &manifest_entry.path);
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let tmp_path = final_path.with_extension("asupersync-tmp");
    fs::write(&tmp_path, decoded).map_err(|err| err.to_string())?;
    fs::rename(&tmp_path, &final_path).map_err(|err| err.to_string())?;
    Ok(final_path)
}

#[test]
fn raptorq_symbols_recover_over_quic_datagrams_with_source_loss() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);
    let object_id = ObjectId::from_u128(0xA7);
    let data = make_data(DATA_LEN);
    let block_k = DATA_LEN.div_ceil(usize::from(SYMBOL_SIZE)); // 8

    // 8 source + 8 repair = 16 symbols.
    let symbols = encode_symbols(object_id, &data, 8);
    assert!(symbols.len() >= block_k, "encoded at least K symbols");

    // Datagram loss: drop 4 SOURCE symbols in transit so the survivors MUST use
    // repair symbols to reconstruct them (16 − 4 = 12 ≥ K = 8, +4 overhead).
    let mut sent = Vec::new();
    let mut dropped_source = 0;
    for s in &symbols {
        if matches!(s.kind(), SymbolKind::Source) && dropped_source < 4 {
            dropped_source += 1;
            continue; // this datagram is "lost"
        }
        sent.push(s.clone());
    }
    assert_eq!(dropped_source, 4, "dropped exactly 4 source symbols");

    let received = spray_and_collect(&cx, &mut client, &mut server, &sent, object_id);
    assert_eq!(
        received.len(),
        sent.len(),
        "bridge delivered every sent symbol"
    );
    assert_eq!(server.datagrams_received(), sent.len() as u64);

    let decoded = recover_object(object_id, DATA_LEN, &received)
        .expect("K-of-N survivors recover the object despite the lost source symbols");
    assert_eq!(decoded, data, "recovered bytes match the original exactly");
}

#[test]
fn authenticated_symbols_recover_over_quic_datagrams_with_source_loss() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);
    let auth = SecurityContext::for_testing(0xB4A6_0001);
    let object_id = ObjectId::from_u128(0xA17);
    let data = make_data(DATA_LEN);
    let block_k = DATA_LEN.div_ceil(usize::from(SYMBOL_SIZE)); // 8

    let symbols = encode_symbols(object_id, &data, 8);
    let mut sent = Vec::new();
    let mut dropped_source = 0usize;
    for s in &symbols {
        if matches!(s.kind(), SymbolKind::Source) && dropped_source < 4 {
            dropped_source += 1;
            continue;
        }
        sent.push(s.clone());
    }
    assert_eq!(dropped_source, 4);
    assert!(sent.len() >= block_k);

    let received =
        spray_and_collect_authenticated(&cx, &mut client, &mut server, &sent, object_id, &auth);
    assert_eq!(received.len(), sent.len());
    assert_eq!(server.datagrams_received(), sent.len() as u64);

    let decoded = recover_object_authenticated(object_id, DATA_LEN, &received, auth.clone())
        .expect("matching auth key verifies symbols and recovers after source loss");
    assert_eq!(decoded, data);

    let wrong_key = SecurityContext::for_testing(0xB4A6_0002);
    assert!(
        recover_object_authenticated(object_id, DATA_LEN, &received, wrong_key).is_err(),
        "a receiver with the wrong key must fail closed instead of decoding"
    );
}

#[test]
fn multi_block_object_recovers_over_quic_datagrams_with_cross_block_source_loss() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);
    let object_id = ObjectId::from_u128(0xC9);
    let data_len = MAX_BLOCK_SIZE + usize::from(SYMBOL_SIZE) * 4;
    let data = make_data(data_len);

    let symbols = encode_symbols(object_id, &data, 4);
    assert!(
        symbols.iter().any(|s| s.sbn() == 1),
        "payload must span at least two source blocks"
    );

    let mut dropped_block0 = 0usize;
    let mut dropped_block1 = 0usize;
    let mut sent = Vec::new();
    for s in &symbols {
        if matches!(s.kind(), SymbolKind::Source) && s.sbn() == 0 && dropped_block0 < 2 {
            dropped_block0 += 1;
            continue;
        }
        if matches!(s.kind(), SymbolKind::Source) && s.sbn() == 1 && dropped_block1 < 1 {
            dropped_block1 += 1;
            continue;
        }
        sent.push(s.clone());
    }
    assert_eq!(dropped_block0, 2, "dropped two first-block source symbols");
    assert_eq!(dropped_block1, 1, "dropped one second-block source symbol");

    let received = spray_and_collect(&cx, &mut client, &mut server, &sent, object_id);
    assert_eq!(received.len(), sent.len());
    assert!(
        received.iter().any(|s| s.sbn() == 0) && received.iter().any(|s| s.sbn() == 1),
        "bridge must deliver symbols from both source blocks"
    );

    let decoded = recover_object(object_id, data.len(), &received)
        .expect("multi-block K-of-N survivors recover after cross-block source loss");
    assert_eq!(
        decoded, data,
        "multi-block recovered bytes match the original exactly"
    );
}

#[test]
fn directory_tree_recovers_verifies_and_commits_atomically_after_datagram_loss() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);
    let entries = tree_fixture();
    let manifest = tree_manifest(&entries);
    let destination = tempfile::tempdir().expect("temp destination");

    assert_eq!(manifest.objects.len(), entries.len());
    assert_eq!(manifest.root_hash, tree_root_hash(&entries));
    assert_eq!(manifest.metadata.get("shape"), Some("directory-tree"));

    for (entry, manifest_entry) in entries.iter().zip(&manifest.objects) {
        assert_eq!(manifest_entry.hash, entry.hash);
        assert_eq!(manifest_entry.path, entry.path);

        let decoded = recover_tree_entry_over_quic(&cx, &mut client, &mut server, entry);
        assert_eq!(decoded, entry.data);

        let committed =
            verify_and_commit_entry(destination.path(), manifest_entry, &decoded).expect("commit");
        assert_eq!(
            fs::read(&committed).expect("read committed entry"),
            entry.data,
            "committed bytes match the recovered tree entry"
        );
    }

    let mut corrupted = entries[0].data.clone();
    corrupted[0] ^= 0x80;
    let corrupt_root = tempfile::tempdir().expect("corrupt temp destination");
    let corrupt_path = destination_path(corrupt_root.path(), &manifest.objects[0].path);
    assert!(
        verify_and_commit_entry(corrupt_root.path(), &manifest.objects[0], &corrupted).is_err(),
        "hash mismatch must fail closed before commit"
    );
    assert!(
        !corrupt_path.exists(),
        "failed verification must leave the final destination absent"
    );
}

#[test]
fn below_threshold_symbol_count_fails_to_recover() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);
    let object_id = ObjectId::from_u128(0xB8);
    let data = make_data(DATA_LEN);
    let block_k = DATA_LEN.div_ceil(usize::from(SYMBOL_SIZE)); // 8

    let symbols = encode_symbols(object_id, &data, 8);
    // Deliver only K − 1 symbols — below the fountain threshold.
    let sent: Vec<Symbol> = symbols.into_iter().take(block_k - 1).collect();
    let received = spray_and_collect(&cx, &mut client, &mut server, &sent, object_id);
    assert_eq!(received.len(), block_k - 1);

    assert!(
        recover_object(object_id, DATA_LEN, &received).is_err(),
        "fewer than K symbols must not decode (fountain threshold, fail closed)"
    );
}
