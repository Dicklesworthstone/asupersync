//! Reject completed manifest chunks before accepting their completing batch.
//!
//! This supplements, never replaces, final on-disk authentication. Resumed
//! receives seed a crossing digest from the checked local prefix on the pool.

use super::*;
use crate::atp::manifest::ChunkBoundary;
use crate::net::atp::chunk::reader::StreamChunk;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

pub(super) fn prepare_integrity(
    writer: &SparseWriter,
    manifest: Arc<Manifest>,
    options: ScopedReceiveOptions,
    expected: Option<&ManifestChunkCommitment>,
    resume_offset: Option<u64>,
) -> Outcome<ReceiveIntegrity, SparseWriterError> {
    prepare_receive(writer, &manifest, options, expected, resume_offset).and_then(|length| {
        let object_id = writer.lock_state().object_id.clone();
        let mut integrity = ReceiveIntegrity {
            manifest, object_id, length, offset: 0, origin: 0, next: 0, partial: None,
        };
        if let Some(start) = resume_offset {
            if let Err(reason) = integrity.seed_prefix(writer, start) {
                return writer.fail_verification(reason).map(|()| integrity);
            }
        }
        Outcome::Ok(integrity)
    })
}

// Incremental rejection is a supplement, never a replacement for the canonical
// file verifier. The immutable manifest remains the only descriptor owner.
// Carry this state through the SAME write job and back with its receipt: no
// borrowed data, extra payload buffer, or hashing task crosses that boundary.
pub(super) struct ReceiveIntegrity {
    pub(super) manifest: Arc<Manifest>,
    object_id: ObjectId,
    pub(super) length: u64,
    offset: u64,
    origin: u64,
    next: usize,
    partial: Option<Sha256>,
}

impl ReceiveIntegrity {
    pub(super) fn validate_ranges(boundaries: &[ChunkBoundary], length: u64) -> Result<(), String> {
        for boundary in boundaries {
            let end = boundary.byte_offset.checked_add(boundary.size_bytes)
                .ok_or_else(|| format!("manifest chunk {} range overflows", boundary.index))?;
            if end > length {
                return Err(format!("manifest chunk {} exceeds receive length", boundary.index));
            }
            // Empty optional hints are valid only with the real empty digest.
            // They need neither a source read nor a staging inode to check.
            if boundary.size_bytes == 0 {
                let empty: [u8; 32] = Sha256::digest(b"").into();
                if boundary.content_hash != empty {
                    return Err(format!("manifest chunk {} hash mismatch", boundary.index));
                }
            }
        }
        Ok(())
    }

    pub(super) fn check_chunk(&mut self, chunk: &StreamChunk) -> Result<(), String> {
        let size = chunk.bytes.len() as u64;
        let end = self.offset.checked_add(size)
            .ok_or_else(|| "receive chunk position overflows".to_owned())?;
        if chunk.boundary.byte_offset.checked_add(self.origin) != Some(self.offset)
            || chunk.boundary.size_bytes != size || size == 0 || end > self.length
        {
            return Err("receive chunk position differs from the declared body".to_owned());
        }
        let object = self.manifest.objects.get(&self.object_id)
            .ok_or_else(|| "selected receive object is missing".to_owned())?;
        while let Some(boundary) = object.chunk_boundaries.get(self.next) {
            if boundary.byte_offset > end {
                break;
            }
            if boundary.size_bytes == 0 {
                // Preflight already checked the empty digest and range.
                self.next += 1;
                continue;
            }
            if boundary.byte_offset == end {
                break;
            }
            let boundary_end = boundary.byte_offset.checked_add(boundary.size_bytes)
                .ok_or_else(|| format!("manifest chunk {} range overflows", boundary.index))?;
            let from = self.offset.max(boundary.byte_offset);
            let to = end.min(boundary_end);
            if from >= to {
                return Err("receive skipped a manifest chunk range".to_owned());
            }
            let actual = if boundary.byte_offset == self.offset && boundary_end == end
                && self.partial.is_none()
            {
                // The canonical reader already hashed this exact owned buffer.
                // Do not hash aligned payloads a second time just for ingress.
                chunk.boundary.content_hash
            } else {
                let first = (from - self.offset) as usize;
                let last = (to - self.offset) as usize;
                self.partial.get_or_insert_with(Sha256::new)
                    .update(&chunk.bytes[first..last]);
                if to < boundary_end {
                    break;
                }
                self.partial.take().expect("partial chunk was hashed").finalize().into()
            };
            if actual != boundary.content_hash {
                return Err(format!("manifest chunk {} hash mismatch", boundary.index));
            }
            self.next += 1;
        }
        self.offset = end;
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<(), String> {
        let object = self.manifest.objects.get(&self.object_id)
            .ok_or_else(|| "selected receive object is missing".to_owned())?;
        // The empty object has no payload batch. Retire its prevalidated empty
        // hints here; nonempty unfinished ranges must never be treated as EOF.
        while let Some(boundary) = object.chunk_boundaries.get(self.next) {
            if boundary.size_bytes != 0 || boundary.byte_offset > self.offset {
                break;
            }
            self.next += 1;
        }
        if self.offset != self.length || self.next != object.chunk_boundaries.len()
            || self.partial.is_some()
        {
            return Err("receive ended before manifest chunk checks completed".to_owned());
        }
        Ok(())
    }
}

impl ReceiveIntegrity {
    // `prepare_receive` already revalidated the contiguous local write receipts.
    // Those describe the receiver's history, not the sender's expected chunks.
    // Authenticate complete prefix descriptors and seed the one crossing the
    // negotiated offset. Gaps need no second read; scratch space is fixed-size.
    fn seed_prefix(&mut self, writer: &SparseWriter, start: u64) -> Result<(), String> {
        if start > self.length {
            return Err("receive integrity offset exceeds object length".to_owned());
        }
        let object = self.manifest.objects.get(&self.object_id)
            .ok_or_else(|| "selected receive object is missing".to_owned())?;
        if start != 0 && !object.chunk_boundaries.is_empty() {
            let _operation = writer.operation.lock();
            let state = writer.lock_state();
            let mut file = state.temp_file.as_ref()
                .ok_or_else(|| "receive integrity prefix has no staging file".to_owned())?
                .try_clone().map_err(|error| error.to_string())?;
            while let Some(boundary) = object.chunk_boundaries.get(self.next) {
                if boundary.byte_offset > start {
                    break;
                }
                if boundary.size_bytes == 0 {
                    self.next += 1;
                    continue;
                }
                if boundary.byte_offset == start {
                    break;
                }
                let end = boundary.byte_offset.checked_add(boundary.size_bytes)
                    .ok_or_else(|| "receive integrity prefix range overflows".to_owned())?;
                if end <= start {
                    let actual = SparseWriter::hash_file_range(
                        &mut file, boundary.byte_offset, boundary.size_bytes,
                    ).map_err(|error| error.to_string())?;
                    if actual != boundary.content_hash {
                        return Err(format!("manifest chunk {} hash mismatch", boundary.index));
                    }
                    self.next += 1;
                } else {
                    file.seek(SeekFrom::Start(boundary.byte_offset))
                        .map_err(|error| error.to_string())?;
                    let mut remaining = start - boundary.byte_offset;
                    let mut hasher = Sha256::new();
                    let mut scratch = [0_u8; 8192];
                    while remaining != 0 {
                        let count = remaining.min(scratch.len() as u64) as usize;
                        file.read_exact(&mut scratch[..count]).map_err(|error| error.to_string())?;
                        hasher.update(&scratch[..count]);
                        remaining -= count as u64;
                    }
                    self.partial = Some(hasher);
                    break;
                }
            }
        }
        self.offset = start;
        self.origin = start;
        Ok(())
    }
}

#[cfg(test)]
#[path = "receive_integrity_tests.rs"]
mod tests;
