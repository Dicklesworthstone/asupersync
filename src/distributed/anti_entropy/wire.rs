//! Separately versioned application frames inside the existing remote protocol.

use super::catalog::{Catalog, CatalogError, Hash, PAGE_HEADER, ROOT_BYTES, add};
#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
use super::catalog::{CatalogEntry, CatalogLimits, branch_hash, bucket, label, leaf_hash, snapshot_hash};
#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
use crate::remote::NodeId;

const REQUEST: &[u8; 8] = b"ASUPCAT\0";
const ROOT: &[u8; 8] = b"ASUPCRT\0";
const NODE: &[u8; 8] = b"ASUPCND\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(crate) struct Root {
    pub snapshot: Hash,
    pub revision: u64,
    pub root: Hash,
    pub entries: usize,
    pub key_bytes: usize,
}

#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(crate) enum Page { Branch(Hash, Hash), Leaf(Vec<CatalogEntry>) }

fn buffer(size: usize, maximum: usize) -> Result<Vec<u8>, CatalogError> {
    if size > maximum { return Err(CatalogError::Limit("response bytes")); }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| CatalogError::Allocation)?;
    if bytes.capacity() > maximum { return Err(CatalogError::Limit("response capacity")); }
    Ok(bytes)
}

#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(crate) fn request(target: &str, node: Option<(Hash, u32)>) -> Result<Vec<u8>, CatalogError> {
    if !label(target) { return Err(CatalogError::Configuration); }
    let size = 14 + target.len() + if node.is_some() { 36 } else { 0 };
    let mut bytes = buffer(size, 305)?;
    bytes.extend_from_slice(REQUEST);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.push(u8::from(node.is_some()));
    bytes.push(target.len() as u8);
    bytes.extend_from_slice(target.as_bytes());
    if let Some((snapshot, index)) = node {
        bytes.extend_from_slice(&snapshot);
        bytes.extend_from_slice(&index.to_le_bytes());
    }
    Ok(bytes)
}

struct Reader<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CatalogError> {
        let end = add(self.offset, n)?;
        let value = self.bytes.get(self.offset..end).ok_or(CatalogError::Format)?;
        self.offset = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, CatalogError> { Ok(self.take(1)?[0]) }
    #[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
    fn u16(&mut self) -> Result<u16, CatalogError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| CatalogError::Format)?))
    }
    fn u32(&mut self) -> Result<u32, CatalogError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| CatalogError::Format)?))
    }
    #[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
    fn u64(&mut self) -> Result<u64, CatalogError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| CatalogError::Format)?))
    }
    fn hash(&mut self) -> Result<Hash, CatalogError> { self.take(32)?.try_into().map_err(|_| CatalogError::Format) }
    fn done(&self) -> Result<(), CatalogError> {
        if self.offset == self.bytes.len() { Ok(()) } else { Err(CatalogError::Format) }
    }
    fn header(&mut self, magic: &[u8; 8]) -> Result<(), CatalogError> {
        if self.take(8)? != magic || self.u32()? != 1 { return Err(CatalogError::Format); }
        Ok(())
    }
}

pub(crate) fn serve(catalog: &Catalog, target: &str, bytes: &[u8]) -> Result<Vec<u8>, CatalogError> {
    if bytes.len() > 305 { return Err(CatalogError::Limit("request bytes")); }
    let mut reader = Reader { bytes, offset: 0 };
    reader.header(REQUEST)?;
    let operation = reader.byte()?;
    let length = usize::from(reader.byte()?);
    if length == 0 || reader.take(length)? != target.as_bytes() { return Err(CatalogError::Unauthorized); }
    if operation == 0 {
        reader.done()?;
        let mut bytes = buffer(ROOT_BYTES, catalog.limits().max_response_bytes)?;
        bytes.extend_from_slice(ROOT);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&catalog.revision().to_le_bytes());
        bytes.push(catalog.limits().depth);
        bytes.extend_from_slice(&catalog.root());
        bytes.extend_from_slice(&catalog.snapshot_id());
        bytes.extend_from_slice(&catalog.limits().fingerprint());
        bytes.extend_from_slice(&(catalog.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(catalog.key_bytes() as u64).to_le_bytes());
        return Ok(bytes);
    }
    if operation != 1 { return Err(CatalogError::Format); }
    if reader.hash()? != catalog.snapshot_id() { return Err(CatalogError::SnapshotChanged); }
    let index = reader.u32()?;
    reader.done()?;
    if catalog.node(index).is_none() { return Err(CatalogError::Format); }
    let page = catalog.page(index);
    let size = if let Some(page) = page {
        page.iter().try_fold(PAGE_HEADER, |total, entry| add(total, add(42, entry.key.len())?))?
    } else { 113 };
    let mut bytes = buffer(size, catalog.limits().max_response_bytes)?;
    bytes.extend_from_slice(NODE);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&catalog.snapshot_id());
    bytes.extend_from_slice(&index.to_le_bytes());
    bytes.push(u8::from(page.is_some()));
    if let Some(page) = page {
        bytes.extend_from_slice(&(page.len() as u32).to_le_bytes());
        for entry in page {
            bytes.extend_from_slice(&(entry.key.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&entry.key);
            bytes.extend_from_slice(&entry.value_hash);
            bytes.extend_from_slice(&entry.value_bytes.to_le_bytes());
        }
    } else {
        bytes.extend_from_slice(&catalog.node(index * 2).ok_or(CatalogError::Format)?);
        bytes.extend_from_slice(&catalog.node(index * 2 + 1).ok_or(CatalogError::Format)?);
    }
    Ok(bytes)
}

#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(crate) fn root(bytes: &[u8], origin: &NodeId, limits: CatalogLimits) -> Result<Root, CatalogError> {
    limits.validate()?;
    if bytes.len() != ROOT_BYTES || bytes.len() > limits.max_response_bytes { return Err(CatalogError::Format); }
    let mut reader = Reader { bytes, offset: 0 };
    reader.header(ROOT)?;
    let revision = reader.u64()?;
    if reader.byte()? != limits.depth { return Err(CatalogError::Configuration); }
    let root = reader.hash()?;
    let snapshot = reader.hash()?;
    if reader.hash()? != limits.fingerprint() { return Err(CatalogError::Configuration); }
    let entries = usize::try_from(reader.u64()?).map_err(|_| CatalogError::Overflow)?;
    let key_bytes = usize::try_from(reader.u64()?).map_err(|_| CatalogError::Overflow)?;
    reader.done()?;
    if entries > limits.max_entries || key_bytes > limits.max_total_key_bytes {
        return Err(CatalogError::Limit("source catalog"));
    }
    if snapshot_hash(origin, revision, limits, root, entries, key_bytes) != snapshot {
        return Err(CatalogError::Integrity);
    }
    Ok(Root { snapshot, revision, root, entries, key_bytes })
}

#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(crate) fn page(bytes: &[u8], root: Root, limits: CatalogLimits, index: u32, expected: Hash)
    -> Result<Page, CatalogError>
{
    let leaves = limits.validate()?;
    if bytes.len() > limits.max_response_bytes { return Err(CatalogError::Limit("response bytes")); }
    if index == 0 || index as usize >= leaves * 2 { return Err(CatalogError::Format); }
    let mut reader = Reader { bytes, offset: 0 };
    reader.header(NODE)?;
    if reader.hash()? != root.snapshot { return Err(CatalogError::SnapshotChanged); }
    if reader.u32()? != index { return Err(CatalogError::Format); }
    let kind = reader.byte()?;
    if (index as usize) < leaves {
        if kind != 0 { return Err(CatalogError::Format); }
        let left = reader.hash()?;
        let right = reader.hash()?;
        reader.done()?;
        if branch_hash(limits.depth, index, left, right) != expected { return Err(CatalogError::Integrity); }
        return Ok(Page::Branch(left, right));
    }
    if kind != 1 { return Err(CatalogError::Format); }
    let count = reader.u32()? as usize;
    if count > limits.max_page_entries || count > root.entries
        || count > bytes.len().saturating_sub(PAGE_HEADER) / 43
    { return Err(CatalogError::Limit("leaf entries")); }
    let entry_bytes = count.checked_mul(std::mem::size_of::<CatalogEntry>()).ok_or(CatalogError::Overflow)?;
    if entry_bytes > limits.max_retained_bytes { return Err(CatalogError::Limit("page bytes")); }
    let mut entries: Vec<CatalogEntry> = Vec::new();
    entries.try_reserve_exact(count).map_err(|_| CatalogError::Allocation)?;
    let mut retained = entries.capacity().checked_mul(std::mem::size_of::<CatalogEntry>()).ok_or(CatalogError::Overflow)?;
    if retained > limits.max_retained_bytes { return Err(CatalogError::Limit("page bytes")); }
    let mut key_bytes = 0usize;
    for _ in 0..count {
        let length = usize::from(reader.u16()?);
        if length == 0 || length > limits.max_key_bytes { return Err(CatalogError::Limit("key bytes")); }
        key_bytes = add(key_bytes, length)?;
        if key_bytes > root.key_bytes { return Err(CatalogError::Limit("source key bytes")); }
        let key = reader.take(length)?;
        if bucket(limits.depth, key) != index as usize - leaves
            || entries.last().is_some_and(|entry| entry.key.as_slice() >= key)
        { return Err(CatalogError::Format); }
        if add(retained, length)? > limits.max_retained_bytes { return Err(CatalogError::Limit("page bytes")); }
        let mut owned = Vec::new();
        owned.try_reserve_exact(length).map_err(|_| CatalogError::Allocation)?;
        retained = add(retained, owned.capacity())?;
        if retained > limits.max_retained_bytes { return Err(CatalogError::Limit("page bytes")); }
        owned.extend_from_slice(key);
        entries.push(CatalogEntry { key: owned, value_hash: reader.hash()?, value_bytes: reader.u64()? });
    }
    reader.done()?;
    if leaf_hash(limits.depth, index, &entries) != expected { return Err(CatalogError::Integrity); }
    Ok(Page::Leaf(entries))
}
