//! Durable fixed-chunk continuation for the authenticated native QUIC path.
//!
//! The persistent file is private recovery evidence, never the final output.
//! Reconnect uses a fresh challenged manifest and rehashes every reused range.
//! The existing append journal supplies authenticated, torn-tail-safe receipts;
//! a payload sync always precedes its Verified -> Written receipt pair.
//! The caller protects cache ancestry. Held descriptor/path checks detect local
//! replacement; they are not an openat-style confinement guarantee for hostile
//! concurrent changes to the destination's ancestors.

use super::{
    AuthMode, AuthenticatedSymbol, AuthenticationTag, DeltaObjectRequest, Frame,
    QuicDeltaSessionContext, QuicTransportError, SecurityContext, TransferManifest,
};

pub(super) const SELECTOR: &str = "authenticated_resumable_fixed_chunks_v1";
const OFFER_EXTENSION: u16 = 0x5157;
const OFFER_DOMAIN: &[u8] = b"atp-quic-resumable-fixed-chunks-v1";
const MAX_CHUNKS: usize = 4096;
const CHUNK_BYTES: usize = 256 * 1024;
const MAX_BYTES: u64 = MAX_CHUNKS as u64 * CHUNK_BYTES as u64;

pub(super) fn selected(request: &DeltaObjectRequest) -> bool {
    request.fallback_reason.as_deref() == Some(SELECTOR)
}

pub(super) fn supported(manifest: &TransferManifest) -> bool {
    super::quic_delta_manifest_entry(manifest).is_some()
        && !super::delta_cdc::is_cdc(manifest)
        && !super::tree_delta::is_tree(manifest)
        && manifest.total_bytes > 0
        && manifest.total_bytes <= MAX_BYTES
        && manifest.delta_manifest.as_ref().is_some_and(|delta| {
            delta.chunk_size == CHUNK_BYTES
                && !delta.chunks.is_empty()
                && delta.chunks.len() <= MAX_CHUNKS
        })
}

pub(super) fn advertise(
    frame: &mut Frame,
    context: &SecurityContext,
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<(), QuicTransportError> {
    if !supported(manifest) || context.mode() != AuthMode::Strict {
        return Err(QuicTransportError::Config(
            "QUIC resume requires strict authority and bounded fixed chunks".to_string(),
        ));
    }
    let symbol = super::quic_delta_manifest_auth_symbol(session, manifest)?;
    let tag = context.derive_context(OFFER_DOMAIN).sign_symbol_tag(&symbol);
    frame.header.extensions.insert(OFFER_EXTENSION, tag.as_bytes().to_vec());
    Ok(())
}

pub(super) fn offered(
    frame: &Frame,
    context: &SecurityContext,
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<bool, QuicTransportError> {
    let Some(bytes) = frame.header.extensions.get(&OFFER_EXTENSION) else {
        return Ok(false);
    };
    let tag = bytes.as_slice().try_into().map_err(|_| {
        QuicTransportError::HandshakeRejected("malformed QUIC resume capability".to_string())
    })?;
    let symbol = super::quic_delta_manifest_auth_symbol(session, manifest)?;
    let mut authenticated = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::from_bytes(tag));
    if !supported(manifest)
        || context.mode() != AuthMode::Strict
        || context.derive_context(OFFER_DOMAIN).verify_authenticated_symbol(&mut authenticated).is_err()
        || !authenticated.is_verified()
    {
        return Err(QuicTransportError::HandshakeRejected(
            "QUIC resume capability authentication failed".to_string(),
        ));
    }
    Ok(true)
}

#[cfg(feature = "tls")]
mod storage {
    use super::{MAX_BYTES, MAX_CHUNKS, SELECTOR, supported};
    use super::super::{
        BTreeMap, CasChunkRef, ContentId, Cx, DeltaChunkWire, DeltaObjectRequest, DeltaWireMode,
        Digest, Path, PathBuf, PersistentChunkManifest, QuicConfig, QuicTransportError,
        Sha256, TransferManifest, delta_chunks, hex_encode, quic_decode_delta_root,
    };
    use crate::atp::journal::{AppendJournal, JournalConfig, JournalRecord, TransferResumeStatus};
    use crate::atp::manifest::MerkleRoot;
    use crate::atp::object::ObjectId;
    use crate::security::{AuthKey, AuthenticationTag};
    use crate::types::Outcome;
    use parking_lot::Mutex;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::sync::Arc;

    const MAX_HISTORY_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_RECORDS: usize = MAX_CHUNKS * 4 + 1;
    const MAX_JOURNAL_FILES: usize = 4;
    const JOURNAL_KEY_DOMAIN: &[u8] = b"atp-quic-resume-private-journal-key-v1";

    struct State {
        // The original payload inode is also the exclusive cache lock. Every
        // in-flight blocking job owns Store, so dropping a receive cannot unlock
        // it while a syscall still runs. This path is never removed/replaced.
        payload: File,
        directory: File,
        journal_directory: File,
        journal: AppendJournal,
        key: AuthKey,
        records: usize,
        failed: bool,
        durable: BTreeMap<u32, DeltaChunkWire>,
    }

    pub(in super::super) struct Store {
        root: PathBuf,
        payload_path: PathBuf,
        transfer: String,
        total_bytes: u64,
        expected: Vec<DeltaChunkWire>,
        state: Mutex<State>,
        #[cfg(feature = "test-internals")]
        progress: Arc<crate::sync::atomic::AtomicU64>,
    }

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn journal_result<T>(outcome: Outcome<T, crate::atp::journal::append_journal::JournalError>) -> io::Result<T> {
        match outcome {
            Outcome::Ok(value) => Ok(value),
            Outcome::Err(error) => Err(invalid(&format!("QUIC resume journal: {error}"))),
            Outcome::Cancelled(_) => Err(io::Error::new(io::ErrorKind::Interrupted, "QUIC resume journal cancelled")),
            Outcome::Panicked(_) => Err(io::Error::other("QUIC resume journal panicked")),
        }
    }

    fn checkpoint(cx: &Cx) -> io::Result<()> {
        cx.checkpoint().map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "QUIC resume cancelled"))
    }

    async fn blocking<T, F>(cx: &Cx, work: F) -> Result<T, QuicTransportError>
    where
        T: Send + 'static,
        F: FnOnce(Cx) -> io::Result<T> + Send + 'static,
    {
        if !cx.capabilities().io {
            return Err(QuicTransportError::Config("QUIC resume requires the caller's IO capability".to_string()));
        }
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let mut task = cx.spawn_blocking_drained(move |child| {
            if !child.capabilities().io {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                    "QUIC resume storage owner lacks IO capability"));
            }
            work(child)
        }).map_err(|error| {
            QuicTransportError::Source(format!("admit owned QUIC resume storage: {error}"))
        })?;
        task.join().await.map_err(|error| {
            if cx.checkpoint().is_err() { QuicTransportError::Cancelled }
            else { QuicTransportError::Source(format!("retire QUIC resume storage: {error}")) }
        })?.map_err(|error| delta_chunks::io_error(cx, error))
    }

    fn regular(path: &Path) -> io::Result<std::fs::Metadata> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("QUIC resume requires regular private files"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(invalid("QUIC resume refuses multiply linked files"));
            }
        }
        Ok(metadata)
    }

    fn directory(path: &Path) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("QUIC resume requires a real private directory"));
        }
        Ok(())
    }

    fn safe_open_options() -> OpenOptions {
        let options = std::fs::OpenOptions::new();
        #[cfg(unix)]
        let options = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = options;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
            options
        };
        options
    }

    fn same_handle(path: &Path, file: &File, is_directory: bool) -> io::Result<()> {
        let named = std::fs::symlink_metadata(path)?;
        let held = file.metadata()?;
        if named.file_type().is_symlink()
            || (is_directory && (!named.is_dir() || !held.is_dir()))
            || (!is_directory && (!named.is_file() || !held.is_file()))
        {
            return Err(invalid("QUIC resume storage handle changed kind"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if named.dev() != held.dev() || named.ino() != held.ino()
                || (!is_directory && (named.nlink() != 1 || held.nlink() != 1))
            {
                return Err(invalid("QUIC resume storage path no longer names its owned inode"));
            }
        }
        Ok(())
    }

    fn open_read(path: &Path, is_directory: bool) -> io::Result<File> {
        let mut options = safe_open_options();
        options.read(true);
        #[cfg(unix)]
        if is_directory {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_DIRECTORY);
        }
        let file = options.open(path)?;
        same_handle(path, &file, is_directory)?;
        Ok(file)
    }

    fn make_directory(path: &Path) -> io::Result<()> {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => directory(path),
            Err(error) => Err(error),
        }
    }

    // Bound bytes and files before AppendJournal's recovery reader materializes
    // an index. A summary limit by itself would run too late to bound reopen.
    fn journal_budget(path: &Path) -> io::Result<(usize, u64)> {
        let mut count = 0usize;
        let mut bytes = 0u64;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            count += 1;
            if count > MAX_JOURNAL_FILES {
                return Err(invalid("QUIC resume journal file budget exceeded"));
            }
            let metadata = regular(&entry.path())?;
            bytes = bytes.checked_add(metadata.len()).ok_or_else(|| invalid("QUIC resume history overflow"))?;
            if bytes > MAX_HISTORY_BYTES {
                return Err(invalid("QUIC resume journal byte budget exceeded"));
            }
        }
        Ok((count, bytes))
    }

    fn cache_identity(manifest: &TransferManifest) -> Result<[u8; 32], QuicTransportError> {
        let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
            QuicTransportError::Control("QUIC resume lacks a fixed manifest".to_string())
        })?;
        let encoded = serde_json::to_vec(&(manifest.root_name.as_str(), delta))
            .map_err(|error| QuicTransportError::Control(format!("encode QUIC resume identity: {error}")))?;
        let mut hash = Sha256::new();
        hash.update(b"ATP-QUIC-DURABLE-FIXED-CACHE-V1\0");
        hash.update(encoded);
        Ok(hash.finalize().into())
    }

    fn verify_range(cx: &Cx, file: &mut File, chunk: &DeltaChunkWire) -> io::Result<()> {
        file.seek(SeekFrom::Start(chunk.entry_offset))?;
        let mut bytes = vec![0u8; 64 * 1024];
        let mut left = chunk.size_bytes;
        let mut hash = ContentId::streaming();
        while left != 0 {
            checkpoint(cx)?;
            let len = usize::try_from(left.min(bytes.len() as u64)).expect("bounded buffer");
            file.read_exact(&mut bytes[..len])?;
            hash.update(&bytes[..len]);
            left -= len as u64;
        }
        if hash.finalize().to_hex() != chunk.content_id_hex {
            return Err(invalid("QUIC resume payload differs from its authenticated chunk"));
        }
        Ok(())
    }

    fn open(
        cx: &Cx,
        root: PathBuf,
        transfer: String,
        identity: [u8; 32],
        key: AuthKey,
        manifest: TransferManifest,
        timestamp: u64,
    ) -> io::Result<Store> {
        checkpoint(cx)?;
        let parent = root.parent().ok_or_else(|| invalid("QUIC resume root has no parent"))?;
        directory(parent)?;
        make_directory(&root)?;
        let directory = open_read(&root, true)?;
        let payload_path = root.join("payload");
        let mut options = safe_open_options();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut payload = match options.open(&payload_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                regular(&payload_path)?;
                safe_open_options().read(true).write(true).open(&payload_path)?
            }
            Err(error) => return Err(error),
        };
        payload.try_lock().map_err(io::Error::from)?;
        same_handle(&root, &directory, true)?;
        same_handle(&payload_path, &payload, false)?;
        if regular(&payload_path)?.len() > manifest.total_bytes || manifest.total_bytes > MAX_BYTES {
            return Err(invalid("QUIC resume payload exceeds its object budget"));
        }
        let journal_path = root.join("journal");
        make_directory(&journal_path)?;
        let journal_directory = open_read(&journal_path, true)?;
        let (journal_files, _) = journal_budget(&journal_path)?;
        // Persist both original inodes and directory entries before a journal
        // receipt can claim that reopening them is possible after a crash.
        payload.sync_all()?;
        directory.sync_all()?;
        open_read(parent, true)?.sync_all()?;
        let config = JournalConfig {
            base_dir: journal_path.clone(),
            max_journal_size: MAX_HISTORY_BYTES,
            recent_entries_limit: 0,
            force_sync: true,
            write_buffer_size: 16 * 1024,
            max_generations: 2,
            enable_detailed_logs: false,
        };
        let mut journal = journal_result(AppendJournal::new(config, key.clone()))?;
        // A torn latest generation makes AppendJournal choose a fresh file.
        // Reserve that file before its first append, rather than admitting four
        // files and discovering a fifth only on the next reopen.
        let next_file = journal_path.join(format!("journal_gen_{:06}.dat", journal.get_stats().generation));
        match std::fs::symlink_metadata(&next_file) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if journal_files >= MAX_JOURNAL_FILES {
                    return Err(invalid("QUIC resume journal generation budget exhausted"));
                }
            }
            Err(error) => return Err(error),
        }
        if journal.get_stats().total_entries > MAX_RECORDS as u64 {
            return Err(invalid("QUIC resume journal record budget exceeded"));
        }
        let mut summary = journal_result(journal.get_resume_summary_with_limits(
            &transfer, MAX_RECORDS, MAX_CHUNKS, MAX_HISTORY_BYTES,
        ))?;
        if summary.status == TransferResumeStatus::Unknown {
            if journal.get_stats().total_entries != 0 {
                return Err(invalid("QUIC resume journal contains another object's history"));
            }
            if journal_budget(&journal_path)?.1 > MAX_HISTORY_BYTES - 4096 {
                return Err(invalid("QUIC resume journal has no room for an offer"));
            }
            journal_result(journal.append(JournalRecord::Offer {
                transfer_id: transfer.clone(), object_id: ObjectId::content(ContentId::new(identity)),
                manifest_root: MerkleRoot::new(identity), total_size: manifest.total_bytes,
                timestamp, auth_tag: AuthenticationTag::from_bytes([0; 32]),
            }.with_signature(&key)))?;
            summary = journal_result(journal.get_resume_summary_with_limits(
                &transfer, MAX_RECORDS, MAX_CHUNKS, MAX_HISTORY_BYTES,
            ))?;
        }
        if !summary.is_resumable() || summary.total_size != Some(manifest.total_bytes) {
            return Err(invalid("QUIC resume journal has no matching resumable offer"));
        }
        let entries = journal_result(journal.get_transfer_entries(&transfer))?;
        if entries.len() as u64 != journal.get_stats().total_entries {
            return Err(invalid("QUIC resume journal has foreign or missing history"));
        }
        if !matches!(entries.first().map(|entry| &entry.record), Some(JournalRecord::Offer {
            object_id, manifest_root, total_size, ..
        }) if *object_id == ObjectId::content(ContentId::new(identity))
            && *manifest_root == MerkleRoot::new(identity) && *total_size == manifest.total_bytes)
        {
            return Err(invalid("QUIC resume journal identity differs from the challenged manifest"));
        }
        let layout = manifest.delta_manifest.as_ref().ok_or_else(|| invalid("QUIC resume manifest disappeared"))?;
        let by_offset: BTreeMap<_, _> = layout.chunks.iter().map(|chunk| (chunk.stream_offset, chunk)).collect();
        let mut durable = BTreeMap::new();
        for receipt in &summary.durable_chunks {
            checkpoint(cx)?;
            let chunk = by_offset.get(&receipt.chunk_offset).ok_or_else(|| invalid("QUIC resume receipt has unknown geometry"))?;
            if receipt.chunk_size != chunk.size_bytes
                || hex_encode(&receipt.chunk_hash) != chunk.content_id_hex
            {
                return Err(invalid("QUIC resume receipt does not match the authenticated chunk"));
            }
            verify_range(cx, &mut payload, chunk)?;
            durable.insert(chunk.index, (*chunk).clone());
        }
        #[cfg(feature = "test-internals")]
        let progress = Arc::new(crate::sync::atomic::AtomicU64::new(summary.durable_bytes));
        #[cfg(feature = "test-internals")]
        register_progress(parent.to_path_buf(), &progress);
        let records = usize::try_from(journal.get_stats().total_entries)
            .map_err(|_| invalid("QUIC resume journal record count overflow"))?;
        same_handle(&root, &directory, true)?;
        same_handle(&payload_path, &payload, false)?;
        same_handle(&journal_path, &journal_directory, true)?;
        Ok(Store {
            root, payload_path, transfer, total_bytes: manifest.total_bytes,
            expected: layout.chunks.clone(),
            state: Mutex::new(State {
                payload, directory, journal_directory, journal, key, records, failed: false, durable,
            }),
            #[cfg(feature = "test-internals")]
            progress,
        })
    }

    impl Store {
        /// Copy only a fully verified network chunk; sync it before recording
        /// reuse authority. The source is ordinary ephemeral receive staging.
        pub(in super::super) async fn checkpoint(
            self: &Arc<Self>, cx: &Cx, chunk: &DeltaChunkWire, source: &Path,
        ) -> Result<(), QuicTransportError> {
            let store = Arc::clone(self);
            let chunk = chunk.clone();
            let source = source.to_path_buf();
            let timestamp = cx.now().as_nanos();
            blocking(cx, move |child| {
                store.checkpoint_sync(&child, &chunk, &source, timestamp)
            }).await
        }

        fn checkpoint_sync(&self, cx: &Cx, chunk: &DeltaChunkWire, source: &Path, timestamp: u64) -> io::Result<()> {
            checkpoint(cx)?;
            if self.expected.get(chunk.index as usize) != Some(chunk) {
                return Err(invalid("QUIC resume checkpoint differs from its admitted manifest"));
            }
            let mut state = self.state.lock();
            if state.failed || state.records.checked_add(2).is_none_or(|count| count > MAX_RECORDS) {
                return Err(invalid("QUIC resume cache is failed or exhausted"));
            }
            if let Some(previous) = state.durable.get(&chunk.index) {
                return if previous == chunk { Ok(()) } else { Err(invalid("QUIC resume chunk changed identity")) };
            }
            same_handle(&self.root, &state.directory, true)?;
            same_handle(&self.payload_path, &state.payload, false)?;
            same_handle(&self.root.join("journal"), &state.journal_directory, true)?;
            if regular(&self.payload_path)?.len() > self.total_bytes {
                return Err(invalid("QUIC resume payload exceeds its object budget"));
            }
            regular(source)?;
            // Both fixed-size records plus framing fit comfortably in 4 KiB.
            if journal_budget(&self.root.join("journal"))?.1 > MAX_HISTORY_BYTES - 4096 {
                return Err(invalid("QUIC resume journal byte budget exhausted"));
            }
            let mut source = open_read(source, false)?;
            verify_range(cx, &mut source, chunk)?;
            source.seek(SeekFrom::Start(chunk.entry_offset))?;
            // Any partial storage effect poisons this owner; a later attempt
            // must reopen and authenticate the actual durable journal tail.
            state.failed = true;
            state.payload.seek(SeekFrom::Start(chunk.entry_offset))?;
            let mut bytes = vec![0u8; 64 * 1024];
            let mut left = chunk.size_bytes;
            let mut hash = ContentId::streaming();
            while left != 0 {
                checkpoint(cx)?;
                let len = usize::try_from(left.min(bytes.len() as u64)).expect("bounded buffer");
                source.read_exact(&mut bytes[..len])?;
                hash.update(&bytes[..len]);
                state.payload.write_all(&bytes[..len])?;
                left -= len as u64;
            }
            let hash = hash.finalize();
            if hash.to_hex() != chunk.content_id_hex {
                return Err(invalid("QUIC receive staging changed during checkpoint"));
            }
            state.payload.sync_all()?;
            state.directory.sync_all()?;
            same_handle(&self.root, &state.directory, true)?;
            same_handle(&self.payload_path, &state.payload, false)?;
            same_handle(&self.root.join("journal"), &state.journal_directory, true)?;
            let verified = JournalRecord::ChunkVerified {
                transfer_id: self.transfer.clone(), chunk_offset: chunk.stream_offset,
                chunk_size: chunk.size_bytes, verified_hash: *hash.hash(), timestamp,
                auth_tag: AuthenticationTag::from_bytes([0; 32]),
            }.with_signature(&state.key);
            let written = JournalRecord::ChunkWritten {
                transfer_id: self.transfer.clone(), chunk_offset: chunk.stream_offset,
                chunk_size: chunk.size_bytes, file_path: "payload".to_string(), timestamp,
                auth_tag: AuthenticationTag::from_bytes([0; 32]),
            }.with_signature(&state.key);
            journal_result(state.journal.append(verified))?;
            journal_result(state.journal.append(written))?;
            same_handle(&self.root, &state.directory, true)?;
            same_handle(&self.payload_path, &state.payload, false)?;
            same_handle(&self.root.join("journal"), &state.journal_directory, true)?;
            state.records += 2;
            state.durable.insert(chunk.index, chunk.clone());
            state.failed = false;
            #[cfg(feature = "test-internals")]
            self.progress.fetch_add(chunk.size_bytes, crate::sync::atomic::Ordering::Release);
            Ok(())
        }
    }

    pub(in super::super) async fn plan(
        cx: &Cx, dest_dir: &Path, config: &QuicConfig, manifest: &TransferManifest,
    ) -> Result<delta_chunks::ReceivePlan, QuicTransportError> {
        if !supported(manifest) {
            return Err(QuicTransportError::Control("unsupported QUIC resume manifest".to_string()));
        }
        let identity = cache_identity(manifest)?;
        let transfer = format!("quic-resume-{}", hex_encode(&identity));
        let root = dest_dir.join(format!(".atp-{transfer}"));
        let context = super::super::quic_delta_control_auth_context(config).ok_or_else(|| {
            QuicTransportError::Config("QUIC resume lost strict delta authority".to_string())
        })?;
        // This private HMAC output is never sent or logged. It is unrelated to
        // the public capability tag and binds cache authentication to this key.
        let derived = context.sign_domain_payload(JOURNAL_KEY_DOMAIN, &identity);
        let key = AuthKey::from_hmac_derived(*derived.as_bytes()).map_err(|error| {
            QuicTransportError::Config(format!("derive QUIC resume journal key: {error}"))
        })?;
        cx.with_ambient(super::super::prepare_quic_destination_root(dest_dir)).await?;
        cx.with_ambient(super::super::reject_quic_destination_symlink_prefix(dest_dir, &root)).await?;
        let owned_manifest = manifest.clone();
        let timestamp = cx.now().as_nanos();
        let store = Arc::new(blocking(cx, move |child| {
            open(&child, root, transfer, identity, key, owned_manifest, timestamp)
        }).await?);
        let mut reusable = BTreeMap::new();
        for chunk in store.state.lock().durable.values() {
            reusable.entry(chunk.content_id_hex.clone()).or_insert(delta_chunks::ReusableRange {
                path: store.payload_path.clone(), offset: chunk.entry_offset, size: chunk.size_bytes,
            });
        }
        if let Some(baseline) = cx.with_ambient(delta_chunks::plan(cx, dest_dir, config, manifest)).await? {
            for (content_id, range) in baseline.reusable {
                reusable.entry(content_id).or_insert(range);
            }
        }
        let layout = manifest.delta_manifest.as_ref().expect("validated resume manifest");
        let mut missing_chunks = Vec::new();
        let mut missing_bytes = 0u64;
        let mut have_chunks = Vec::new();
        let mut have_bytes = 0u64;
        for chunk in &layout.chunks {
            if reusable.get(&chunk.content_id_hex).is_none_or(|range| range.size != chunk.size_bytes) {
                missing_chunks.push(chunk.clone());
                missing_bytes += chunk.size_bytes;
            } else {
                // The advertised root commits to the actual ordered have-set,
                // including the empty set on a fresh resumable attempt.
                have_chunks.push(CasChunkRef {
                    index: u32::try_from(have_chunks.len()).expect("bounded have-set"),
                    byte_offset: have_bytes, size_bytes: chunk.size_bytes,
                    content_id: ContentId::new(quic_decode_delta_root(&chunk.content_id_hex, "resume have-set")?),
                });
                have_bytes += chunk.size_bytes;
            }
        }
        let have = PersistentChunkManifest::new(hex_encode(&identity), have_chunks).map_err(|error| {
            QuicTransportError::Control(format!("build QUIC resume have-set: {error}"))
        })?;
        let request = DeltaObjectRequest {
            mode: DeltaWireMode::DeltaChunks, fallback_reason: Some(SELECTOR.to_string()),
            sender_merkle_root_hex: layout.merkle_root_hex.clone(),
            receiver_merkle_root_hex: Some(have.merkle_root.to_hex()),
            shared_chunks: (layout.chunks.len() - missing_chunks.len()) as u64,
            missing_bytes, stale_chunks: 0, missing_chunks,
        };
        delta_chunks::validate_request(manifest, &request)?;
        super::super::quic_progress(format_args!(
            "receiver: resume transfer={} reused_chunks={} missing_chunks={} missing_bytes={}",
            manifest.transfer_id, request.shared_chunks, request.missing_chunks.len(), request.missing_bytes,
        ));
        Ok(delta_chunks::ReceivePlan {
            request, baseline: dest_dir.to_path_buf(), reusable, resume: Some(store),
        })
    }

    #[cfg(feature = "test-internals")]
    type Progress = std::sync::OnceLock<Mutex<BTreeMap<PathBuf, std::sync::Weak<crate::sync::atomic::AtomicU64>>>>;
    #[cfg(feature = "test-internals")]
    static PROGRESS: Progress = std::sync::OnceLock::new();

    #[cfg(feature = "test-internals")]
    fn register_progress(destination: PathBuf, progress: &Arc<crate::sync::atomic::AtomicU64>) {
        let mut all = PROGRESS.get_or_init(Mutex::default).lock();
        all.retain(|_, value| value.strong_count() != 0);
        all.insert(destination, Arc::downgrade(progress));
    }

    /// A state witness after both payload and journal durability barriers.
    #[cfg(feature = "test-internals")]
    pub(in super::super) fn checkpoint_bytes(destination: &Path) -> Option<u64> {
        let progress = PROGRESS.get()?.lock().get(destination)?.upgrade()?;
        Some(progress.load(crate::sync::atomic::Ordering::Acquire))
    }

    #[cfg(all(test, unix))]
    mod tests {
        use super::{
            AuthKey, Cx, File, MAX_HISTORY_BYTES, OpenOptions, Path, PathBuf, Read,
            Seek, SeekFrom, Store, TransferManifest, Write, cache_identity, hex_encode, open,
        };

        fn fixture() -> (tempfile::TempDir, PathBuf, TransferManifest, Vec<u8>) {
            let dir = tempfile::tempdir().unwrap();
            let (manifest, bytes) = super::super::tests::manifest();
            let source = dir.path().join("source");
            std::fs::write(&source, &bytes).unwrap();
            (dir, source, manifest, bytes)
        }

        fn reopen(destination: &Path, manifest: &TransferManifest, seed: u64) -> std::io::Result<Store> {
            let identity = cache_identity(manifest).unwrap();
            let transfer = format!("quic-resume-{}", hex_encode(&identity));
            open(&Cx::for_testing(), destination.join(format!(".atp-{transfer}")),
                transfer, identity, AuthKey::from_seed(seed), manifest.clone(), 123)
        }

        #[test]
        fn durable_resume_reopens_only_receipted_chunks_and_keeps_one_exclusive_owner() {
            let (dir, source, manifest, bytes) = fixture();
            let chunks = &manifest.delta_manifest.as_ref().unwrap().chunks;
            let store = reopen(dir.path(), &manifest, 138).unwrap();
            store.checkpoint_sync(&Cx::for_testing(), &chunks[0], &source, 124).unwrap();
            assert!(reopen(dir.path(), &manifest, 138).is_err(), "live owner retains its lock");
            {
                let mut state = store.state.lock();
                state.payload.seek(SeekFrom::Start(chunks[1].entry_offset)).unwrap();
                // A process can die after payload I/O but before its receipt.
                state.payload.write_all(&bytes[super::super::CHUNK_BYTES..][..1024]).unwrap();
                state.payload.sync_all().unwrap();
            }
            drop(store);
            let mut reconnect = manifest.clone();
            reconnect.transfer_id = "cd".repeat(32);
            assert_eq!(cache_identity(&manifest).unwrap(), cache_identity(&reconnect).unwrap());
            let store = reopen(dir.path(), &reconnect, 138).unwrap();
            assert_eq!(store.state.lock().durable.keys().copied().collect::<Vec<_>>(), vec![0]);
            store.checkpoint_sync(&Cx::for_testing(), &chunks[1], &source, 125).unwrap();
            drop(store);
            let store = reopen(dir.path(), &reconnect, 138).unwrap();
            assert_eq!(store.state.lock().durable.keys().copied().collect::<Vec<_>>(), vec![0, 1]);
        }

        #[test]
        fn durable_resume_rejects_corrupt_payload_and_wrong_journal_authority() {
            let (dir, source, manifest, _) = fixture();
            let store = reopen(dir.path(), &manifest, 138).unwrap();
            let payload_path = store.payload_path.clone();
            let chunk = &manifest.delta_manifest.as_ref().unwrap().chunks[0];
            store.checkpoint_sync(&Cx::for_testing(), chunk, &source, 124).unwrap();
            drop(store);
            assert!(reopen(dir.path(), &manifest, 139).is_err(), "CRC is not journal authority");
            let mut file = OpenOptions::new().write(true).open(&payload_path).unwrap();
            file.write_all(&[0x99]).unwrap();
            file.sync_all().unwrap();
            drop(file);
            assert!(reopen(dir.path(), &manifest, 138).is_err(), "journal receipts never substitute for a payload rehash");
        }

        #[test]
        fn durable_resume_recovers_valid_prefix_across_a_torn_journal_tail() {
            let (dir, source, manifest, _) = fixture();
            let store = reopen(dir.path(), &manifest, 138).unwrap();
            let chunks = &manifest.delta_manifest.as_ref().unwrap().chunks;
            store.checkpoint_sync(&Cx::for_testing(), &chunks[0], &source, 124).unwrap();
            let journal_dir = store.root.join("journal");
            drop(store);
            let mut generations: Vec<_> = std::fs::read_dir(&journal_dir).unwrap()
                .map(|entry| entry.unwrap().path()).collect();
            generations.sort();
            let mut tail = OpenOptions::new().append(true).open(generations.last().unwrap()).unwrap();
            tail.write_all(&[64, 0, 0, 0, 1, 2]).unwrap();
            tail.sync_all().unwrap();
            drop(tail);
            let store = reopen(dir.path(), &manifest, 138).unwrap();
            assert_eq!(store.state.lock().durable.len(), 1);
            store.checkpoint_sync(&Cx::for_testing(), &chunks[1], &source, 125).unwrap();
            drop(store);
            assert_eq!(reopen(dir.path(), &manifest, 138).unwrap().state.lock().durable.len(), 2);
        }

        #[test]
        fn durable_resume_refuses_oversized_history_before_journal_recovery() {
            let (dir, _, manifest, _) = fixture();
            let store = reopen(dir.path(), &manifest, 138).unwrap();
            let oversized = store.root.join("journal").join("untrusted.dat");
            drop(store);
            let file = File::create(&oversized).unwrap();
            file.set_len(MAX_HISTORY_BYTES + 1).unwrap();
            drop(file);
            assert!(reopen(dir.path(), &manifest, 138).is_err());
        }

        #[test]
        fn durable_resume_reserves_a_generation_slot_before_recovering_a_torn_tail() {
            let (dir, _, manifest, _) = fixture();
            let store = reopen(dir.path(), &manifest, 138).unwrap();
            let journal = store.root.join("journal");
            drop(store);
            for generation in 1..4 {
                std::fs::write(journal.join(format!("journal_gen_{generation:06}.dat")), [64, 0]).unwrap();
            }
            assert!(reopen(dir.path(), &manifest, 138).is_err());
            assert_eq!(std::fs::read_dir(&journal).unwrap().count(), 4,
                "recovery must not exceed the admitted generation count");
        }

        #[test]
        fn durable_resume_bad_source_never_gains_a_written_receipt() {
            let (dir, source, manifest, _) = fixture();
            let store = reopen(dir.path(), &manifest, 138).unwrap();
            let chunk = &manifest.delta_manifest.as_ref().unwrap().chunks[0];
            let mut foreign = chunk.clone();
            foreign.entry_offset = super::MAX_BYTES;
            assert!(store.checkpoint_sync(&Cx::for_testing(), &foreign, &source, 124).is_err());
            std::fs::write(&source, vec![0xff; super::super::CHUNK_BYTES]).unwrap();
            assert!(store.checkpoint_sync(&Cx::for_testing(), chunk, &source, 124).is_err());
            assert!(store.state.lock().durable.is_empty());
            assert_eq!(store.state.lock().payload.metadata().unwrap().len(), 0);
            drop(store);
            let store = reopen(dir.path(), &manifest, 138).unwrap();
            assert!(store.state.lock().durable.is_empty());
        }

        #[test]
        fn durable_resume_refuses_symlinked_or_multiply_linked_payloads() {
            let (dir, source, manifest, bytes) = fixture();
            let identity = cache_identity(&manifest).unwrap();
            let root = dir.path().join(format!(".atp-quic-resume-{}", hex_encode(&identity)));
            std::fs::create_dir(&root).unwrap();
            std::os::unix::fs::symlink(&source, root.join("payload")).unwrap();
            assert!(reopen(dir.path(), &manifest, 138).is_err());
            let other = tempfile::tempdir().unwrap();
            let other_root = other.path().join(root.file_name().unwrap());
            std::fs::create_dir(&other_root).unwrap();
            std::fs::hard_link(&source, other_root.join("payload")).unwrap();
            assert!(reopen(other.path(), &manifest, 138).is_err());
            let mut current = Vec::new();
            File::open(&source).unwrap().read_to_end(&mut current).unwrap();
            assert_eq!(current, bytes, "cache admission must not alter unrelated source files");
        }

        #[test]
        fn durable_resume_refuses_payload_and_directory_substitution_after_admission() {
            for replace_directory in [false, true] {
                let (dir, source, manifest, bytes) = fixture();
                let store = reopen(dir.path(), &manifest, 138).unwrap();
                let chunks = &manifest.delta_manifest.as_ref().unwrap().chunks;
                store.checkpoint_sync(&Cx::for_testing(), &chunks[0], &source, 124).unwrap();
                let retained = dir.path().join("retained-owned-inode");
                if replace_directory {
                    std::fs::rename(&store.root, &retained).unwrap();
                    std::fs::create_dir(&store.root).unwrap();
                } else {
                    std::fs::rename(&store.payload_path, &retained).unwrap();
                }
                std::fs::write(&store.payload_path, b"unrelated replacement").unwrap();
                assert!(store.checkpoint_sync(&Cx::for_testing(), &chunks[1], &source, 125).is_err());
                assert_eq!(std::fs::read(&store.payload_path).unwrap(), b"unrelated replacement");
                let retained_payload = if replace_directory { retained.join("payload") } else { retained };
                assert_eq!(std::fs::read(retained_payload).unwrap(), bytes[..super::super::CHUNK_BYTES]);
                assert_eq!(store.state.lock().durable.len(), 1,
                    "a replacement path cannot split the lock and receipt owners");
            }
        }
    }
}

#[cfg(feature = "tls")]
pub(super) use storage::{Store, plan};
#[cfg(all(feature = "tls", feature = "test-internals"))]
pub(super) use storage::checkpoint_bytes;

#[cfg(test)]
#[path = "resume_tests.rs"]
mod tests;
