//! Stable, structural schema fingerprints for typed named computations.
//!
//! This is the foundation of the typed `spawn_remote` registry (bead
//! `asupersync-dist-otp-completeness-8y37kz.7`). Remote computations are named
//! and carry serialized input/output payloads; without a schema check, a
//! wrong-schema bug surfaces as an opaque deserialization failure at the remote
//! node — or, worse, a silent misinterpretation. This module lets each
//! computation advertise a content-hashed **schema fingerprint** that travels
//! in the spawn envelope, so a mismatch is caught (and *named*) up front.
//!
//! # Critical design decision: structural fingerprint, NOT `TypeId`
//!
//! The fingerprint is derived from a [`SchemaDescriptor`] — a canonical,
//! declaration-order structural description of a type's wire shape (field names
//! and types) — and hashed with a fixed FNV-1a-64 function over a canonical
//! byte encoding. It deliberately does **not** use [`std::any::TypeId`] or any
//! memory-layout/`type_name` value, because those are neither stable across
//! compiler versions nor meaningful across two independently-built nodes. Two
//! nodes that were compiled separately but declare the same logical schema must
//! agree on the fingerprint; two that differ in any wire-visible way must not.
//!
//! # Layering
//!
//! This module is a pure typing layer: it has no I/O and no dependency on the
//! spawn protocol. The typed envelope fields + dispatcher in `remote.rs` and
//! the `#[remote_computation]` derive (which will auto-generate
//! [`HasSchema`] impls) build on top of it in sibling slices of the bead.

use std::fmt;

/// Canonical, declaration-order structural description of a value's wire schema.
///
/// Equality and the derived fingerprint are intentionally structural: anything
/// that changes the serialized shape (a primitive type, a field name, field
/// order, an added/removed field, a renamed struct/enum) changes the descriptor
/// and therefore the [`SchemaFingerprint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaDescriptor {
    /// A scalar/leaf type, identified by a stable canonical name (e.g. `"u64"`).
    Primitive(&'static str),
    /// The unit type `()`.
    Unit,
    /// An optional value (`Option<T>`).
    Option(Box<SchemaDescriptor>),
    /// A homogeneous sequence (`Vec<T>`, `[T]`).
    Seq(Box<SchemaDescriptor>),
    /// A key/value map.
    Map(Box<SchemaDescriptor>, Box<SchemaDescriptor>),
    /// A fixed-arity tuple, in element order.
    Tuple(Vec<SchemaDescriptor>),
    /// A named struct with fields in declaration order.
    Struct {
        /// The struct's canonical name.
        name: &'static str,
        /// Fields as `(name, schema)` in declaration order.
        fields: Vec<(&'static str, SchemaDescriptor)>,
    },
    /// A named enum with variants in declaration order.
    Enum {
        /// The enum's canonical name.
        name: &'static str,
        /// Variants as `(name, payload schema)` in declaration order.
        variants: Vec<(&'static str, SchemaDescriptor)>,
    },
}

impl SchemaDescriptor {
    /// A leaf/primitive schema with the given canonical name.
    #[must_use]
    pub const fn primitive(name: &'static str) -> Self {
        Self::Primitive(name)
    }

    /// An `Option<inner>` schema.
    #[must_use]
    pub fn option(inner: Self) -> Self {
        Self::Option(Box::new(inner))
    }

    /// A sequence-of-`inner` schema.
    #[must_use]
    pub fn seq(inner: Self) -> Self {
        Self::Seq(Box::new(inner))
    }

    /// A map schema with the given key and value schemas.
    #[must_use]
    pub fn map(key: Self, value: Self) -> Self {
        Self::Map(Box::new(key), Box::new(value))
    }

    /// A tuple schema from its element schemas, in order.
    #[must_use]
    pub fn tuple(elements: Vec<Self>) -> Self {
        Self::Tuple(elements)
    }

    /// A named struct schema from its fields, in declaration order.
    #[must_use]
    pub fn structure(name: &'static str, fields: Vec<(&'static str, Self)>) -> Self {
        Self::Struct { name, fields }
    }

    /// A named enum schema from its variants, in declaration order.
    #[must_use]
    pub fn enumeration(name: &'static str, variants: Vec<(&'static str, Self)>) -> Self {
        Self::Enum { name, variants }
    }

    /// The content-hashed fingerprint of this schema.
    #[must_use]
    pub fn fingerprint(&self) -> SchemaFingerprint {
        SchemaFingerprint::of(self)
    }

    /// A short, human/agent-readable name for this descriptor's variant.
    const fn kind_name(&self) -> &'static str {
        match self {
            Self::Primitive(_) => "primitive",
            Self::Unit => "unit",
            Self::Option(_) => "option",
            Self::Seq(_) => "seq",
            Self::Map(..) => "map",
            Self::Tuple(_) => "tuple",
            Self::Struct { .. } => "struct",
            Self::Enum { .. } => "enum",
        }
    }

    /// Appends a canonical, deterministic byte encoding of this descriptor to
    /// `out`. The encoding is tag-prefixed and length-delimited so that no two
    /// structurally-distinct descriptors can collide on the encoded bytes (and
    /// therefore — modulo the hash — on the fingerprint).
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Primitive(name) => {
                out.push(0);
                encode_str(name, out);
            }
            Self::Unit => out.push(1),
            Self::Option(inner) => {
                out.push(2);
                inner.canonical_encode(out);
            }
            Self::Seq(inner) => {
                out.push(3);
                inner.canonical_encode(out);
            }
            Self::Map(key, value) => {
                out.push(4);
                key.canonical_encode(out);
                value.canonical_encode(out);
            }
            Self::Tuple(elements) => {
                out.push(5);
                encode_len(elements.len(), out);
                for element in elements {
                    element.canonical_encode(out);
                }
            }
            Self::Struct { name, fields } => {
                out.push(6);
                encode_str(name, out);
                encode_len(fields.len(), out);
                for (field_name, field_schema) in fields {
                    encode_str(field_name, out);
                    field_schema.canonical_encode(out);
                }
            }
            Self::Enum { name, variants } => {
                out.push(7);
                encode_str(name, out);
                encode_len(variants.len(), out);
                for (variant_name, variant_schema) in variants {
                    encode_str(variant_name, out);
                    variant_schema.canonical_encode(out);
                }
            }
        }
    }

    /// Returns the first structural difference between an `expected` schema and
    /// an `actual` one, or `None` if they are identical.
    ///
    /// The reported [`SchemaMismatch`] carries a path into the schema and a
    /// kind naming the difference (primitive/type change, renamed type, missing
    /// or extra field, changed tuple arity) so that agents reading the error
    /// can pinpoint it. A renamed field surfaces as a missing field (its old
    /// name) followed, on a subsequent comparison, by an extra field.
    #[must_use]
    pub fn diff(expected: &Self, actual: &Self) -> Option<SchemaMismatch> {
        diff_at(expected, actual, "$")
    }
}

fn encode_str(value: &str, out: &mut Vec<u8>) {
    encode_len(value.len(), out);
    out.extend_from_slice(value.as_bytes());
}

fn encode_len(len: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(&(len as u64).to_le_bytes());
}

/// FNV-1a 64-bit hash. Fixed constants make the output stable across compiler
/// versions and machines — the property `TypeId` lacks.
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn diff_at(
    expected: &SchemaDescriptor,
    actual: &SchemaDescriptor,
    path: &str,
) -> Option<SchemaMismatch> {
    use SchemaDescriptor as D;
    match (expected, actual) {
        (D::Primitive(e), D::Primitive(a)) => {
            if e == a {
                None
            } else {
                Some(SchemaMismatch::new(
                    path,
                    SchemaMismatchKind::PrimitiveChanged {
                        expected: *e,
                        actual: *a,
                    },
                ))
            }
        }
        (D::Unit, D::Unit) => None,
        (D::Option(e), D::Option(a)) => diff_at(e, a, &format!("{path}?")),
        (D::Seq(e), D::Seq(a)) => diff_at(e, a, &format!("{path}[]")),
        (D::Map(ek, ev), D::Map(ak, av)) => diff_at(ek, ak, &format!("{path}.<key>"))
            .or_else(|| diff_at(ev, av, &format!("{path}.<value>"))),
        (D::Tuple(e), D::Tuple(a)) => {
            if e.len() != a.len() {
                return Some(SchemaMismatch::new(
                    path,
                    SchemaMismatchKind::ArityChanged {
                        expected: e.len(),
                        actual: a.len(),
                    },
                ));
            }
            for (index, (ei, ai)) in e.iter().zip(a.iter()).enumerate() {
                if let Some(mismatch) = diff_at(ei, ai, &format!("{path}.{index}")) {
                    return Some(mismatch);
                }
            }
            None
        }
        (
            D::Struct {
                name: en,
                fields: ef,
            },
            D::Struct {
                name: an,
                fields: af,
            },
        ) => {
            if en != an {
                return Some(SchemaMismatch::new(
                    path,
                    SchemaMismatchKind::NameChanged {
                        expected: (*en).to_string(),
                        actual: (*an).to_string(),
                    },
                ));
            }
            diff_named(ef, af, path)
        }
        (
            D::Enum {
                name: en,
                variants: ev,
            },
            D::Enum {
                name: an,
                variants: av,
            },
        ) => {
            if en != an {
                return Some(SchemaMismatch::new(
                    path,
                    SchemaMismatchKind::NameChanged {
                        expected: (*en).to_string(),
                        actual: (*an).to_string(),
                    },
                ));
            }
            diff_named(ev, av, path)
        }
        (e, a) => Some(SchemaMismatch::new(
            path,
            SchemaMismatchKind::KindChanged {
                expected: e.kind_name(),
                actual: a.kind_name(),
            },
        )),
    }
}

fn diff_named(
    expected: &[(&'static str, SchemaDescriptor)],
    actual: &[(&'static str, SchemaDescriptor)],
    path: &str,
) -> Option<SchemaMismatch> {
    for (name, expected_schema) in expected {
        match actual.iter().find(|(other, _)| other == name) {
            Some((_, actual_schema)) => {
                if let Some(mismatch) =
                    diff_at(expected_schema, actual_schema, &format!("{path}.{name}"))
                {
                    return Some(mismatch);
                }
            }
            None => {
                return Some(SchemaMismatch::new(
                    path,
                    SchemaMismatchKind::FieldMissing {
                        field: (*name).to_string(),
                    },
                ));
            }
        }
    }
    for (name, _) in actual {
        if !expected.iter().any(|(other, _)| other == name) {
            return Some(SchemaMismatch::new(
                path,
                SchemaMismatchKind::FieldExtra {
                    field: (*name).to_string(),
                },
            ));
        }
    }
    None
}

/// A content-hashed fingerprint of a [`SchemaDescriptor`].
///
/// Stable across compiler versions and independently-built nodes (it is a fixed
/// hash over the canonical structural encoding, never `TypeId`/layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaFingerprint(u64);

impl SchemaFingerprint {
    /// Computes the fingerprint of a schema descriptor.
    #[must_use]
    pub fn of(descriptor: &SchemaDescriptor) -> Self {
        let mut buffer = Vec::new();
        descriptor.canonical_encode(&mut buffer);
        Self(fnv1a64(&buffer))
    }

    /// The raw 64-bit fingerprint value (e.g. to embed in a spawn envelope).
    #[must_use]
    pub const fn to_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SchemaFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// A located structural difference between two schemas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaMismatch {
    /// A path into the schema where the difference was found (`$` is the root).
    pub path: String,
    /// What differs at that path.
    pub kind: SchemaMismatchKind,
}

impl SchemaMismatch {
    fn new(path: &str, kind: SchemaMismatchKind) -> Self {
        Self {
            path: path.to_string(),
            kind,
        }
    }
}

impl fmt::Display for SchemaMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "schema mismatch at `{}`: {}", self.path, self.kind)
    }
}

impl std::error::Error for SchemaMismatch {}

/// The specific way two schemas differ at a point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaMismatchKind {
    /// The descriptor variant changed (e.g. `struct` vs `seq`).
    KindChanged {
        /// The expected descriptor kind.
        expected: &'static str,
        /// The actual descriptor kind.
        actual: &'static str,
    },
    /// A primitive's canonical type name changed.
    PrimitiveChanged {
        /// The expected primitive name.
        expected: &'static str,
        /// The actual primitive name.
        actual: &'static str,
    },
    /// A named struct/enum was renamed.
    NameChanged {
        /// The expected type name.
        expected: String,
        /// The actual type name.
        actual: String,
    },
    /// A field/variant present in the expected schema is absent from the actual.
    FieldMissing {
        /// The missing field/variant name.
        field: String,
    },
    /// A field/variant present in the actual schema is absent from the expected.
    FieldExtra {
        /// The unexpected field/variant name.
        field: String,
    },
    /// A tuple's arity changed.
    ArityChanged {
        /// The expected element count.
        expected: usize,
        /// The actual element count.
        actual: usize,
    },
}

impl fmt::Display for SchemaMismatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KindChanged { expected, actual } => {
                write!(f, "kind changed: expected `{expected}`, found `{actual}`")
            }
            Self::PrimitiveChanged { expected, actual } => write!(
                f,
                "primitive type changed: expected `{expected}`, found `{actual}`"
            ),
            Self::NameChanged { expected, actual } => {
                write!(f, "type renamed: expected `{expected}`, found `{actual}`")
            }
            Self::FieldMissing { field } => write!(f, "missing field `{field}`"),
            Self::FieldExtra { field } => write!(f, "unexpected extra field `{field}`"),
            Self::ArityChanged { expected, actual } => {
                write!(f, "tuple arity changed: expected {expected}, found {actual}")
            }
        }
    }
}

/// A type that can describe its own wire schema for typed remote computations.
///
/// The `#[remote_computation]` derive (a sibling slice of this bead) will
/// auto-generate these impls from a type's declaration; until then, types may
/// implement it by hand. Primitives, `Option`, `Vec`, `Box`, the unit type, and
/// small tuples are provided here.
///
/// ```
/// use asupersync::distributed::computation_schema::HasSchema;
///
/// // Fingerprints are structural and stable, not based on `TypeId`.
/// assert_eq!(u64::schema_fingerprint(), u64::schema_fingerprint());
/// assert_ne!(u64::schema_fingerprint(), u32::schema_fingerprint());
/// assert_ne!(<Vec<u8>>::schema_fingerprint(), <Vec<u16>>::schema_fingerprint());
/// ```
pub trait HasSchema {
    /// The canonical structural schema of this type.
    fn schema() -> SchemaDescriptor;

    /// The content-hashed fingerprint of this type's schema.
    #[must_use]
    fn schema_fingerprint() -> SchemaFingerprint {
        SchemaFingerprint::of(&Self::schema())
    }
}

macro_rules! impl_primitive_schema {
    ($($t:ty => $name:literal),+ $(,)?) => {
        $(
            impl HasSchema for $t {
                fn schema() -> SchemaDescriptor {
                    SchemaDescriptor::Primitive($name)
                }
            }
        )+
    };
}

impl_primitive_schema! {
    u8 => "u8", u16 => "u16", u32 => "u32", u64 => "u64", u128 => "u128", usize => "usize",
    i8 => "i8", i16 => "i16", i32 => "i32", i64 => "i64", i128 => "i128", isize => "isize",
    bool => "bool", char => "char", f32 => "f32", f64 => "f64", String => "String",
}

impl HasSchema for () {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::Unit
    }
}

impl<T: HasSchema> HasSchema for Option<T> {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::option(T::schema())
    }
}

impl<T: HasSchema> HasSchema for Vec<T> {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::seq(T::schema())
    }
}

impl<T: HasSchema> HasSchema for Box<T> {
    fn schema() -> SchemaDescriptor {
        T::schema()
    }
}

impl<A: HasSchema, B: HasSchema> HasSchema for (A, B) {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::tuple(vec![A::schema(), B::schema()])
    }
}

impl<A: HasSchema, B: HasSchema, C: HasSchema> HasSchema for (A, B, C) {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::tuple(vec![A::schema(), B::schema(), C::schema()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person() -> SchemaDescriptor {
        SchemaDescriptor::structure(
            "Person",
            vec![
                ("id", u64::schema()),
                ("name", String::schema()),
                ("tags", <Vec<String>>::schema()),
            ],
        )
    }

    #[test]
    fn fingerprint_is_deterministic_and_distinct() {
        // AC3: stable across recomputation; distinct for distinct structure.
        assert_eq!(person().fingerprint(), person().fingerprint());
        assert_eq!(u64::schema_fingerprint(), u64::schema_fingerprint());
        assert_ne!(u64::schema_fingerprint(), u32::schema_fingerprint());
        assert_ne!(
            <Vec<u8>>::schema_fingerprint(),
            <Vec<u16>>::schema_fingerprint()
        );
        assert_ne!(
            <Option<u64>>::schema_fingerprint(),
            u64::schema_fingerprint()
        );
    }

    #[test]
    fn fingerprint_not_type_id_based() {
        // Two independently-constructed-but-identical descriptors agree.
        let a = SchemaDescriptor::structure("P", vec![("x", u8::schema())]);
        let b = SchemaDescriptor::structure("P", vec![("x", u8::schema())]);
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn diff_detects_type_change() {
        let expected = person();
        let actual = SchemaDescriptor::structure(
            "Person",
            vec![
                ("id", u32::schema()), // changed u64 -> u32
                ("name", String::schema()),
                ("tags", <Vec<String>>::schema()),
            ],
        );
        let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
        assert_eq!(mismatch.path, "$.id");
        assert!(matches!(
            mismatch.kind,
            SchemaMismatchKind::PrimitiveChanged {
                expected: "u64",
                actual: "u32"
            }
        ));
    }

    #[test]
    fn diff_detects_missing_field() {
        let expected = person();
        let actual = SchemaDescriptor::structure(
            "Person",
            vec![("id", u64::schema()), ("name", String::schema())], // dropped "tags"
        );
        let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
        assert!(matches!(
            mismatch.kind,
            SchemaMismatchKind::FieldMissing { ref field } if field == "tags"
        ));
    }

    #[test]
    fn diff_detects_extra_field() {
        let expected = SchemaDescriptor::structure("P", vec![("a", u8::schema())]);
        let actual =
            SchemaDescriptor::structure("P", vec![("a", u8::schema()), ("b", u8::schema())]);
        let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
        assert!(matches!(
            mismatch.kind,
            SchemaMismatchKind::FieldExtra { ref field } if field == "b"
        ));
    }

    #[test]
    fn diff_detects_rename() {
        let expected = SchemaDescriptor::structure("Old", vec![("a", u8::schema())]);
        let actual = SchemaDescriptor::structure("New", vec![("a", u8::schema())]);
        let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
        assert!(matches!(
            mismatch.kind,
            SchemaMismatchKind::NameChanged { .. }
        ));
    }

    #[test]
    fn identical_schema_has_no_diff() {
        assert!(SchemaDescriptor::diff(&person(), &person()).is_none());
    }

    #[test]
    fn mismatch_messages_name_the_difference() {
        // AC2: messages are agent-readable and name the difference.
        let expected = person();
        let actual = SchemaDescriptor::structure(
            "Person",
            vec![
                ("id", u32::schema()),
                ("name", String::schema()),
                ("tags", <Vec<String>>::schema()),
            ],
        );
        let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
        let rendered = mismatch.to_string();
        assert!(rendered.contains("$.id"), "rendered: {rendered}");
        assert!(rendered.contains("u64"), "rendered: {rendered}");
        assert!(rendered.contains("u32"), "rendered: {rendered}");
    }
}
