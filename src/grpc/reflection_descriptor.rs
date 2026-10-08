//! Immutable protobuf descriptor catalogs for gRPC server reflection.
//!
//! Decode a `FileDescriptorSet` emitted by `protoc --include_imports`. The
//! catalog indexes names and imports, but serves the ORIGINAL serialized
//! `FileDescriptorProto` bytes, retaining options, source information and
//! unknown fields. It is not a protobuf type checker or a source compiler.
//! Loading a catalog performs no I/O and grants no network access.

use crate::bytes::Bytes;
use super::Status;
use prost::Message as _;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Maximum encoded descriptor-set input admitted by [`ReflectionDescriptorSet::decode`].
pub const MAX_REFLECTION_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILES: usize = 1024;
const MAX_SYMBOLS: usize = 65_536;
const MAX_DEPTH: usize = 64;
const MAX_NAME_BYTES: usize = 1024;

/// A validated, immutable index over explicitly supplied protobuf descriptors.
///
/// The entire import closure must be present. Duplicate files/symbols/extension
/// numbers, missing imports, import cycles and excessive size/depth are refused
/// before a catalog is returned. The limits bound admitted catalogs, not the
/// allocator overhead of decoding caller-supplied configuration. File lookups
/// return a deterministic root-first dependency closure with each file once.
/// Callers exposing this data remotely must separately authorize that access.
#[derive(Clone)]
pub struct ReflectionDescriptorSet {
    files: BTreeMap<String, File>,
    symbols: BTreeMap<String, String>,
    messages: BTreeSet<String>,
    services: BTreeSet<String>,
    extensions: BTreeMap<String, BTreeMap<i32, String>>,
}

#[derive(Clone)]
struct File {
    bytes: Bytes,
    imports: Vec<String>,
}

impl std::fmt::Debug for ReflectionDescriptorSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReflectionDescriptorSet")
            .field("files", &self.files.len())
            .field("symbols", &self.symbols.len())
            .field("services", &self.services.len())
            .finish_non_exhaustive()
    }
}

impl ReflectionDescriptorSet {
    /// Decode a complete binary `google.protobuf.FileDescriptorSet`.
    ///
    /// Names and imports are checked for unambiguous lookup. Field types,
    /// options, editions and application-level schema compatibility are not
    /// type-checked; use descriptors produced by the protobuf compiler.
    pub fn decode(encoded: &[u8]) -> Result<Self, Status> {
        if encoded.len() > MAX_REFLECTION_DESCRIPTOR_BYTES {
            return Err(Status::resource_exhausted("reflection descriptor bytes exceeded"));
        }
        let set = WireSet::decode(encoded)
            .map_err(|_| Status::invalid_argument("invalid protobuf descriptor set"))?;
        if set.files.len() > MAX_FILES {
            return Err(Status::resource_exhausted("reflection descriptor file limit exceeded"));
        }
        let mut catalog = Self {
            files: BTreeMap::new(),
            symbols: BTreeMap::new(),
            messages: BTreeSet::new(),
            services: BTreeSet::new(),
            extensions: BTreeMap::new(),
        };
        for raw in set.files {
            let info = FileInfo::decode(raw.as_slice())
                .map_err(|_| Status::invalid_argument("invalid protobuf file descriptor"))?;
            let name = info.name.as_deref().unwrap_or_default();
            if name.is_empty() || name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control) {
                return Err(Status::invalid_argument("invalid reflection file name"));
            }
            if catalog.files.contains_key(name) {
                return Err(Status::invalid_argument("duplicate reflection file name"));
            }
            let package = info.package.as_deref().unwrap_or_default();
            if !package.is_empty() && !qualified_name(package) {
                return Err(Status::invalid_argument("invalid protobuf package name"));
            }
            for message in &info.messages {
                catalog.index_message(package, message, name, 0)?;
            }
            for enumeration in &info.enums {
                catalog.index_enum(package, enumeration, name)?;
            }
            for service in &info.services {
                let full = join_name(package, service.name.as_deref())?;
                catalog.insert_symbol(full.clone(), name)?;
                catalog.services.insert(full.clone());
                for method in &service.methods {
                    catalog.insert_symbol(join_name(&full, method.name.as_deref())?, name)?;
                }
            }
            for extension in &info.extensions {
                catalog.index_extension(package, extension, name)?;
            }
            catalog.files.insert(name.to_owned(), File {
                bytes: Bytes::from(raw),
                imports: info.imports,
            });
        }
        catalog.validate_imports()?;
        if catalog.extensions.keys().any(|name| !catalog.messages.contains(name)) {
            return Err(Status::invalid_argument("extension target is not a known message"));
        }
        Ok(catalog)
    }

    /// All supplied file names, in lexical order. These are keys, not filesystem paths.
    pub fn file_names(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// Service names present in the descriptors, in lexical order.
    /// This does not assert that corresponding handlers are registered on a server.
    pub fn service_names(&self) -> impl Iterator<Item = &str> {
        self.services.iter().map(String::as_str)
    }

    /// Find a file and all of its transitive imports without re-encoding them.
    pub fn file_by_name(&self, name: &str) -> Result<Vec<Bytes>, Status> {
        if !self.files.contains_key(name) {
            return Err(Status::not_found("reflection file not found"));
        }
        let mut queue = VecDeque::from([name]);
        let mut visited = BTreeSet::new();
        let mut result = Vec::new();
        while let Some(name) = queue.pop_front() {
            if !visited.insert(name) {
                continue;
            }
            let file = &self.files[name]; // decode validated the complete import closure.
            result.push(file.bytes.clone());
            queue.extend(file.imports.iter().map(String::as_str));
        }
        Ok(result)
    }

    /// Find a service, method, message, field, oneof, enum, enum value or extension.
    /// An optional single leading dot is accepted for fully qualified type names.
    pub fn file_containing_symbol(&self, symbol: &str) -> Result<Vec<Bytes>, Status> {
        let file = self.symbols.get(without_root_dot(symbol))
            .ok_or_else(|| Status::not_found("reflection symbol not found"))?;
        self.file_by_name(file)
    }

    /// Find the file declaring an extension of a message, plus that file's imports.
    pub fn file_containing_extension(&self, message: &str, number: i32) -> Result<Vec<Bytes>, Status> {
        let file = self.extensions.get(without_root_dot(message))
            .and_then(|extensions| extensions.get(&number))
            .ok_or_else(|| Status::not_found("reflection extension not found"))?;
        self.file_by_name(file)
    }

    /// All known extension numbers for a message, sorted and without duplicates.
    /// A known message with no extensions yields an empty list; an unknown type fails.
    pub fn extension_numbers(&self, message: &str) -> Result<Vec<i32>, Status> {
        let message = without_root_dot(message);
        if !self.messages.contains(message) {
            return Err(Status::not_found("reflection message type not found"));
        }
        Ok(self.extensions.get(message)
            .map(|extensions| extensions.keys().copied().collect())
            .unwrap_or_default())
    }

    fn insert_symbol(&mut self, name: String, file: &str) -> Result<(), Status> {
        if self.symbols.len() >= MAX_SYMBOLS {
            return Err(Status::resource_exhausted("reflection symbol limit exceeded"));
        }
        if self.symbols.insert(name, file.to_owned()).is_some() {
            return Err(Status::invalid_argument("duplicate protobuf symbol"));
        }
        Ok(())
    }

    fn index_message(&mut self, parent: &str, message: &MessageInfo, file: &str, depth: usize) -> Result<(), Status> {
        if depth >= MAX_DEPTH {
            return Err(Status::resource_exhausted("reflection message nesting exceeded"));
        }
        let name = join_name(parent, message.name.as_deref())?;
        self.insert_symbol(name.clone(), file)?;
        self.messages.insert(name.clone());
        for field in &message.fields {
            self.insert_symbol(join_name(&name, field.name.as_deref())?, file)?;
        }
        for oneof in &message.oneofs {
            self.insert_symbol(join_name(&name, oneof.name.as_deref())?, file)?;
        }
        for nested in &message.nested {
            self.index_message(&name, nested, file, depth + 1)?;
        }
        for enumeration in &message.enums {
            self.index_enum(&name, enumeration, file)?;
        }
        for extension in &message.extensions {
            self.index_extension(&name, extension, file)?;
        }
        Ok(())
    }

    fn index_enum(&mut self, parent: &str, enumeration: &EnumInfo, file: &str) -> Result<(), Status> {
        self.insert_symbol(join_name(parent, enumeration.name.as_deref())?, file)?;
        // Protobuf enum values live in the ENUM'S ENCLOSING scope, not under its name.
        for value in &enumeration.values {
            self.insert_symbol(join_name(parent, value.name.as_deref())?, file)?;
        }
        Ok(())
    }

    fn index_extension(&mut self, parent: &str, extension: &FieldInfo, file: &str) -> Result<(), Status> {
        self.insert_symbol(join_name(parent, extension.name.as_deref())?, file)?;
        let target = extension.extendee.as_deref().unwrap_or_default();
        // protoc emits an absolute extendee; do not guess how a relative name resolves.
        let target = target.strip_prefix('.')
            .filter(|name| qualified_name(name))
            .ok_or_else(|| Status::invalid_argument("extension target must be fully qualified"))?;
        let number = extension.number.unwrap_or_default();
        if !(1..=536_870_911).contains(&number) || (19_000..=19_999).contains(&number) {
            return Err(Status::invalid_argument("invalid protobuf extension number"));
        }
        if self.extensions.entry(target.to_owned()).or_default()
            .insert(number, file.to_owned()).is_some() {
            return Err(Status::invalid_argument("duplicate protobuf extension number"));
        }
        Ok(())
    }

    fn validate_imports(&self) -> Result<(), Status> {
        let mut remaining = BTreeMap::new();
        let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut ready = VecDeque::new();
        for (name, file) in &self.files {
            let mut unique = BTreeSet::new();
            for import in &file.imports {
                if !self.files.contains_key(import) || !unique.insert(import) {
                    return Err(Status::invalid_argument("missing or duplicate protobuf import"));
                }
                dependents.entry(import).or_default().push(name);
            }
            remaining.insert(name.as_str(), file.imports.len());
            if file.imports.is_empty() {
                ready.push_back(name.as_str());
            }
        }
        let mut visited = 0;
        while let Some(name) = ready.pop_front() {
            visited += 1;
            if let Some(children) = dependents.get(name) {
                for child in children {
                    let count = remaining.get_mut(child).expect("indexed importing file");
                    *count -= 1;
                    if *count == 0 {
                        ready.push_back(child);
                    }
                }
            }
        }
        if visited != self.files.len() {
            return Err(Status::invalid_argument("protobuf import cycle"));
        }
        Ok(())
    }
}

fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn qualified_name(name: &str) -> bool {
    name.len() <= MAX_NAME_BYTES && name.split('.').all(identifier)
}

fn join_name(parent: &str, name: Option<&str>) -> Result<String, Status> {
    let name = name.filter(|name| identifier(name))
        .ok_or_else(|| Status::invalid_argument("invalid protobuf symbol name"))?;
    let full = if parent.is_empty() { name.to_owned() } else { format!("{parent}.{name}") };
    if full.len() > MAX_NAME_BYTES {
        return Err(Status::resource_exhausted("protobuf symbol name limit exceeded"));
    }
    Ok(full)
}

fn without_root_dot(name: &str) -> &str {
    name.strip_prefix('.').unwrap_or(name)
}

// Private indexing projections of google/protobuf/descriptor.proto. Embedded
// FileDescriptorProto messages are initially captured as bytes (the same wire
// type) so serving a descriptor never loses fields unknown to these projections.
#[derive(Clone, PartialEq, prost::Message)]
struct WireSet {
    #[prost(bytes = "vec", repeated, tag = "1")]
    files: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct FileInfo {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(string, optional, tag = "2")]
    package: Option<String>,
    #[prost(string, repeated, tag = "3")]
    imports: Vec<String>,
    #[prost(message, repeated, tag = "4")]
    messages: Vec<MessageInfo>,
    #[prost(message, repeated, tag = "5")]
    enums: Vec<EnumInfo>,
    #[prost(message, repeated, tag = "6")]
    services: Vec<ServiceInfo>,
    #[prost(message, repeated, tag = "7")]
    extensions: Vec<FieldInfo>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct MessageInfo {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(message, repeated, tag = "2")]
    fields: Vec<FieldInfo>,
    #[prost(message, repeated, tag = "3")]
    nested: Vec<Self>,
    #[prost(message, repeated, tag = "4")]
    enums: Vec<EnumInfo>,
    #[prost(message, repeated, tag = "6")]
    extensions: Vec<FieldInfo>,
    #[prost(message, repeated, tag = "8")]
    oneofs: Vec<NameInfo>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct FieldInfo {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(string, optional, tag = "2")]
    extendee: Option<String>,
    #[prost(int32, optional, tag = "3")]
    number: Option<i32>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct EnumInfo {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(message, repeated, tag = "2")]
    values: Vec<NameInfo>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ServiceInfo {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(message, repeated, tag = "2")]
    methods: Vec<NameInfo>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct NameInfo {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
}

#[cfg(test)]
mod tests;
