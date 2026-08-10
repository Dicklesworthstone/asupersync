//! Owned Protocol Buffers authoring derives.
//!
//! The grammar is deliberately small, explicit, and Cargo-only. Every field
//! carries its wire kind and tag at the Rust definition site, so expansion
//! never shells out to `protoc`, reads an ambient registry, or depends on
//! filesystem ordering.

use std::collections::BTreeMap;

use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, quote_spanned};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    Attribute, Data, DataEnum, DataStruct, DeriveInput, Error, Expr, ExprLit, Fields,
    GenericArgument, Ident, Lit, Meta, Path, PathArguments, Result, Token, Type, Variant,
};

const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;
const RESERVED_FIELD_START: u32 = 19_000;
const RESERVED_FIELD_END: u32 = 19_999;

#[derive(Clone)]
enum Kind {
    Double,
    Float,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Fixed32,
    Fixed64,
    Sfixed32,
    Sfixed64,
    Bool,
    String,
    Bytes,
    Message,
    Enumeration(Path),
    Map { key: Box<Self>, value: Box<Self> },
    Oneof,
    UnknownFields,
}

impl Kind {
    fn from_name(name: &str, span: Span) -> Result<Self> {
        match name {
            "double" => Ok(Self::Double),
            "float" => Ok(Self::Float),
            "int32" => Ok(Self::Int32),
            "int64" => Ok(Self::Int64),
            "uint32" => Ok(Self::Uint32),
            "uint64" => Ok(Self::Uint64),
            "sint32" => Ok(Self::Sint32),
            "sint64" => Ok(Self::Sint64),
            "fixed32" => Ok(Self::Fixed32),
            "fixed64" => Ok(Self::Fixed64),
            "sfixed32" => Ok(Self::Sfixed32),
            "sfixed64" => Ok(Self::Sfixed64),
            "bool" => Ok(Self::Bool),
            "string" => Ok(Self::String),
            "bytes" => Ok(Self::Bytes),
            "message" => Ok(Self::Message),
            "enum" | "enumeration" => Ok(Self::Enumeration(syn::parse_quote!(i32))),
            _ => Err(Error::new(
                span,
                format!(
                    "unsupported protobuf kind `{name}`; expected a scalar, string, bytes, \
                     message, enumeration, map, oneof, or unknown_fields"
                ),
            )),
        }
    }

    const fn is_packable(&self) -> bool {
        matches!(
            self,
            Self::Double
                | Self::Float
                | Self::Int32
                | Self::Int64
                | Self::Uint32
                | Self::Uint64
                | Self::Sint32
                | Self::Sint64
                | Self::Fixed32
                | Self::Fixed64
                | Self::Sfixed32
                | Self::Sfixed64
                | Self::Bool
                | Self::Enumeration(_)
        )
    }

    const fn is_map_key(&self) -> bool {
        matches!(
            self,
            Self::Int32
                | Self::Int64
                | Self::Uint32
                | Self::Uint64
                | Self::Sint32
                | Self::Sint64
                | Self::Fixed32
                | Self::Fixed64
                | Self::Sfixed32
                | Self::Sfixed64
                | Self::Bool
                | Self::String
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Cardinality {
    Singular,
    Optional,
    Repeated,
}

struct FieldSpec {
    ident: Ident,
    ty: Type,
    kind: Kind,
    cardinality: Cardinality,
    packed: bool,
    tag: Option<u32>,
    oneof_tags: Vec<u32>,
    span: Span,
}

struct ParsedAttribute {
    kind: Option<Kind>,
    cardinality: Cardinality,
    packed: bool,
    tag: Option<u32>,
    oneof_tags: Vec<u32>,
    map_key: Option<Kind>,
    map_value: Option<Kind>,
}

impl Default for ParsedAttribute {
    fn default() -> Self {
        Self {
            kind: None,
            cardinality: Cardinality::Singular,
            packed: false,
            tag: None,
            oneof_tags: Vec::new(),
            map_key: None,
            map_value: None,
        }
    }
}

fn proto_attribute(attributes: &[Attribute]) -> Result<&Attribute> {
    let mut found = attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("proto"));
    let Some(attribute) = found.next() else {
        return Err(Error::new(
            attributes
                .first()
                .map_or_else(Span::call_site, Attribute::span),
            "every derived protobuf field or oneof variant requires exactly one #[proto(...)] attribute",
        ));
    };
    if let Some(duplicate) = found.next() {
        return Err(Error::new(
            duplicate.span(),
            "duplicate #[proto(...)] attribute",
        ));
    }
    Ok(attribute)
}

fn literal_u32(expr: &Expr, label: &str) -> Result<u32> {
    let Expr::Lit(ExprLit {
        lit: Lit::Int(value),
        ..
    }) = expr
    else {
        return Err(Error::new(
            expr.span(),
            format!("`{label}` must be an integer literal"),
        ));
    };
    value.base10_parse()
}

fn literal_string(expr: &Expr, label: &str) -> Result<String> {
    let Expr::Lit(ExprLit {
        lit: Lit::Str(value),
        ..
    }) = expr
    else {
        return Err(Error::new(
            expr.span(),
            format!("`{label}` must be a string literal"),
        ));
    };
    Ok(value.value())
}

fn set_kind(target: &mut Option<Kind>, kind: Kind, span: Span) -> Result<()> {
    if target.is_some() {
        return Err(Error::new(
            span,
            "a protobuf field must declare exactly one wire kind",
        ));
    }
    *target = Some(kind);
    Ok(())
}

fn set_cardinality(
    parsed: &mut ParsedAttribute,
    cardinality: Cardinality,
    span: Span,
) -> Result<()> {
    if parsed.cardinality != Cardinality::Singular {
        return Err(Error::new(
            span,
            "protobuf cardinality may be declared only once",
        ));
    }
    parsed.cardinality = cardinality;
    Ok(())
}

fn parse_path_meta(parsed: &mut ParsedAttribute, path: &Path) -> Result<()> {
    let Some(ident) = path.get_ident() else {
        return Err(Error::new(
            path.span(),
            "expected a single protobuf keyword",
        ));
    };
    let name = ident.to_string();
    match name.as_str() {
        "optional" => set_cardinality(parsed, Cardinality::Optional, ident.span()),
        "repeated" => set_cardinality(parsed, Cardinality::Repeated, ident.span()),
        "packed" => {
            parsed.packed = true;
            Ok(())
        }
        "map" => set_kind(
            &mut parsed.kind,
            Kind::Map {
                key: Box::new(Kind::String),
                value: Box::new(Kind::String),
            },
            ident.span(),
        ),
        "oneof" => set_kind(&mut parsed.kind, Kind::Oneof, ident.span()),
        "unknown_fields" => set_kind(&mut parsed.kind, Kind::UnknownFields, ident.span()),
        _ => set_kind(
            &mut parsed.kind,
            Kind::from_name(&name, ident.span())?,
            ident.span(),
        ),
    }
}

fn parse_oneof_tags(expr: &Expr) -> Result<Vec<u32>> {
    let raw = literal_string(expr, "tags")?;
    raw.split(',')
        .map(|component| {
            let component = component.trim();
            if component.is_empty() {
                return Err(Error::new(
                    expr.span(),
                    "`tags` contains an empty field number",
                ));
            }
            component.parse::<u32>().map_err(|_| {
                Error::new(
                    expr.span(),
                    format!("`{component}` is not a valid u32 field number"),
                )
            })
        })
        .collect()
}

fn parse_name_value_meta(
    parsed: &mut ParsedAttribute,
    name_value: &syn::MetaNameValue,
) -> Result<()> {
    if name_value.path.is_ident("tag") {
        if parsed.tag.is_some() {
            return Err(Error::new(name_value.span(), "duplicate protobuf `tag`"));
        }
        parsed.tag = Some(literal_u32(&name_value.value, "tag")?);
    } else if name_value.path.is_ident("tags") {
        if !parsed.oneof_tags.is_empty() {
            return Err(Error::new(name_value.span(), "duplicate protobuf `tags`"));
        }
        parsed.oneof_tags = parse_oneof_tags(&name_value.value)?;
    } else if name_value.path.is_ident("key") {
        let name = literal_string(&name_value.value, "key")?;
        parsed.map_key = Some(Kind::from_name(&name, name_value.value.span())?);
    } else if name_value.path.is_ident("value") {
        let name = literal_string(&name_value.value, "value")?;
        parsed.map_value = Some(Kind::from_name(&name, name_value.value.span())?);
    } else if name_value.path.is_ident("enumeration") {
        let raw = literal_string(&name_value.value, "enumeration")?;
        let path = syn::parse_str::<Path>(&raw).map_err(|error| {
            Error::new(
                name_value.value.span(),
                format!("invalid enumeration type path: {error}"),
            )
        })?;
        set_kind(&mut parsed.kind, Kind::Enumeration(path), name_value.span())?;
    } else {
        return Err(Error::new(
            name_value.span(),
            "unsupported #[proto(...)] argument",
        ));
    }
    Ok(())
}

fn finalize_map_kind(parsed: &mut ParsedAttribute, span: Span) -> Result<()> {
    if !matches!(parsed.kind, Some(Kind::Map { .. })) {
        if parsed.map_key.is_some() || parsed.map_value.is_some() {
            return Err(Error::new(
                span,
                "`key` and `value` are valid only on a `map` field",
            ));
        }
        return Ok(());
    }

    let Some(key) = parsed.map_key.take() else {
        return Err(Error::new(span, "map fields require `key = \"...\"`"));
    };
    let Some(value) = parsed.map_value.take() else {
        return Err(Error::new(span, "map fields require `value = \"...\"`"));
    };
    if !key.is_map_key() {
        return Err(Error::new(
            span,
            "protobuf map keys must be an integer, bool, or string scalar",
        ));
    }
    parsed.kind = Some(Kind::Map {
        key: Box::new(key),
        value: Box::new(value),
    });
    Ok(())
}

fn parse_proto_attribute(attribute: &Attribute) -> Result<ParsedAttribute> {
    let metas = attribute.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
    let mut parsed = ParsedAttribute::default();

    for meta in metas {
        match meta {
            Meta::Path(path) => parse_path_meta(&mut parsed, &path)?,
            Meta::NameValue(name_value) => parse_name_value_meta(&mut parsed, &name_value)?,
            other @ Meta::List(_) => {
                return Err(Error::new(
                    other.span(),
                    "unsupported #[proto(...)] argument",
                ));
            }
        }
    }

    finalize_map_kind(&mut parsed, attribute.span())?;
    Ok(parsed)
}

fn validate_tag(tag: u32, span: Span) -> Result<()> {
    if tag == 0 || tag > MAX_FIELD_NUMBER {
        return Err(Error::new(
            span,
            format!("protobuf tag must be in 1..={MAX_FIELD_NUMBER}"),
        ));
    }
    if (RESERVED_FIELD_START..=RESERVED_FIELD_END).contains(&tag) {
        return Err(Error::new(
            span,
            format!(
                "protobuf tag {tag} is reserved; tags {RESERVED_FIELD_START}..={RESERVED_FIELD_END} cannot be used"
            ),
        ));
    }
    Ok(())
}

fn single_type_argument(ty: &Type, wrapper: &str, span: Span) -> Result<Type> {
    let declaration = match wrapper {
        "Option" => "optional",
        "Vec" => "repeated",
        _ => wrapper,
    };
    let Type::Path(type_path) = ty else {
        return Err(Error::new(
            span,
            format!("`{declaration}` protobuf field must use {wrapper}<T>"),
        ));
    };
    let Some(segment) = type_path.path.segments.last() else {
        return Err(Error::new(span, "empty Rust type path"));
    };
    if segment.ident != wrapper {
        return Err(Error::new(
            span,
            format!("`{declaration}` protobuf field must use {wrapper}<T>"),
        ));
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return Err(Error::new(
            span,
            format!("{wrapper} requires one type argument"),
        ));
    };
    let mut types = arguments.args.iter().filter_map(|argument| {
        if let GenericArgument::Type(ty) = argument {
            Some(ty.clone())
        } else {
            None
        }
    });
    let Some(inner) = types.next() else {
        return Err(Error::new(
            span,
            format!("{wrapper} requires one type argument"),
        ));
    };
    if types.next().is_some() {
        return Err(Error::new(
            span,
            format!("{wrapper} requires one type argument"),
        ));
    }
    Ok(inner)
}

fn map_type_arguments(ty: &Type, span: Span) -> Result<(Type, Type)> {
    let Type::Path(type_path) = ty else {
        return Err(Error::new(
            span,
            "protobuf map field must use BTreeMap<K, V> or HashMap<K, V>",
        ));
    };
    let Some(segment) = type_path.path.segments.last() else {
        return Err(Error::new(span, "empty Rust type path"));
    };
    if segment.ident != "BTreeMap" && segment.ident != "HashMap" {
        return Err(Error::new(
            span,
            "protobuf map field must use BTreeMap<K, V> or HashMap<K, V>",
        ));
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return Err(Error::new(
            span,
            "protobuf map requires key and value types",
        ));
    };
    let types: Vec<_> = arguments
        .args
        .iter()
        .filter_map(|argument| {
            if let GenericArgument::Type(ty) = argument {
                Some(ty.clone())
            } else {
                None
            }
        })
        .collect();
    if types.len() != 2 {
        return Err(Error::new(
            span,
            "protobuf map requires exactly two type arguments",
        ));
    }
    Ok((types[0].clone(), types[1].clone()))
}

fn unknown_field_spec(
    field: &syn::Field,
    ident: Ident,
    parsed: &ParsedAttribute,
    span: Span,
    unknown_seen: &mut bool,
) -> Result<FieldSpec> {
    if *unknown_seen {
        return Err(Error::new(
            span,
            "only one #[proto(unknown_fields)] member is allowed",
        ));
    }
    if parsed.tag.is_some()
        || !parsed.oneof_tags.is_empty()
        || parsed.cardinality != Cardinality::Singular
        || parsed.packed
    {
        return Err(Error::new(
            span,
            "unknown_fields accepts no tag, cardinality, or packed modifier",
        ));
    }
    *unknown_seen = true;
    Ok(FieldSpec {
        ident,
        ty: field.ty.clone(),
        kind: Kind::UnknownFields,
        cardinality: Cardinality::Singular,
        packed: false,
        tag: None,
        oneof_tags: Vec::new(),
        span,
    })
}

fn oneof_field_spec(
    field: &syn::Field,
    ident: Ident,
    mut parsed: ParsedAttribute,
    tags: &mut BTreeMap<u32, Span>,
    span: Span,
) -> Result<FieldSpec> {
    if parsed.tag.is_some() || parsed.oneof_tags.is_empty() {
        return Err(Error::new(
            span,
            "oneof fields require `tags = \"...\"` and do not accept `tag`",
        ));
    }
    if parsed.cardinality != Cardinality::Singular || parsed.packed {
        return Err(Error::new(
            span,
            "oneof fields are already optional and accept no cardinality or packed modifier",
        ));
    }
    let _ = single_type_argument(&field.ty, "Option", span)?;
    parsed.oneof_tags.sort_unstable();
    for &tag in &parsed.oneof_tags {
        validate_tag(tag, span)?;
        if tags.insert(tag, span).is_some() {
            return Err(Error::new(
                span,
                format!("protobuf tag {tag} is declared more than once"),
            ));
        }
    }
    Ok(FieldSpec {
        ident,
        ty: field.ty.clone(),
        kind: Kind::Oneof,
        cardinality: Cardinality::Singular,
        packed: false,
        tag: None,
        oneof_tags: parsed.oneof_tags,
        span,
    })
}

fn regular_field_spec(
    field: &syn::Field,
    ident: Ident,
    parsed: &ParsedAttribute,
    kind: Kind,
    tags: &mut BTreeMap<u32, Span>,
    span: Span,
) -> Result<FieldSpec> {
    let tag = parsed
        .tag
        .ok_or_else(|| Error::new(span, "protobuf field is missing `tag = N`"))?;
    validate_tag(tag, span)?;
    if tags.insert(tag, span).is_some() {
        return Err(Error::new(
            span,
            format!("protobuf tag {tag} is declared more than once"),
        ));
    }
    if parsed.packed && (parsed.cardinality != Cardinality::Repeated || !kind.is_packable()) {
        return Err(Error::new(
            span,
            "`packed` is valid only on a repeated numeric, bool, or enumeration field",
        ));
    }
    if matches!(kind, Kind::Map { .. }) {
        if parsed.cardinality != Cardinality::Singular || parsed.packed {
            return Err(Error::new(
                span,
                "map fields accept no optional, repeated, or packed modifier",
            ));
        }
        let _ = map_type_arguments(&field.ty, span)?;
    } else {
        match parsed.cardinality {
            Cardinality::Singular => {}
            Cardinality::Optional => {
                let _ = single_type_argument(&field.ty, "Option", span)?;
            }
            Cardinality::Repeated => {
                let _ = single_type_argument(&field.ty, "Vec", span)?;
            }
        }
    }
    Ok(FieldSpec {
        ident,
        ty: field.ty.clone(),
        kind,
        cardinality: parsed.cardinality,
        packed: parsed.packed,
        tag: Some(tag),
        oneof_tags: Vec::new(),
        span,
    })
}

fn parse_struct_field(
    field: &syn::Field,
    tags: &mut BTreeMap<u32, Span>,
    unknown_seen: &mut bool,
) -> Result<FieldSpec> {
    let span = field.span();
    let ident = field
        .ident
        .clone()
        .ok_or_else(|| Error::new(span, "expected a named field"))?;
    let parsed = parse_proto_attribute(proto_attribute(&field.attrs)?)?;
    let kind = parsed
        .kind
        .clone()
        .ok_or_else(|| Error::new(span, "missing protobuf wire kind"))?;

    match kind {
        Kind::UnknownFields => unknown_field_spec(field, ident, &parsed, span, unknown_seen),
        Kind::Oneof => oneof_field_spec(field, ident, parsed, tags, span),
        _ => regular_field_spec(field, ident, &parsed, kind, tags, span),
    }
}

fn parse_struct_fields(data: &DataStruct) -> Result<Vec<FieldSpec>> {
    let Fields::Named(fields) = &data.fields else {
        return Err(Error::new(
            data.fields.span(),
            "ProtoMessage supports structs with named fields only",
        ));
    };
    let mut tags = BTreeMap::<u32, Span>::new();
    let mut unknown_seen = false;
    fields
        .named
        .iter()
        .map(|field| parse_struct_field(field, &mut tags, &mut unknown_seen))
        .collect()
}

fn default_test(kind: &Kind, value: &TokenStream2) -> TokenStream2 {
    match kind {
        Kind::Double => quote!(#value != 0.0f64),
        Kind::Float => quote!(#value != 0.0f32),
        Kind::Bool => quote!(#value),
        Kind::String | Kind::Bytes => quote!(!#value.is_empty()),
        Kind::Message | Kind::Map { .. } | Kind::Oneof | Kind::UnknownFields => quote!(true),
        Kind::Enumeration(_) => quote!(#value != 0i32),
        _ => quote!(#value != 0),
    }
}

fn encode_call(
    kind: &Kind,
    encoder: &TokenStream2,
    value: &TokenStream2,
    tag: u32,
) -> TokenStream2 {
    match kind {
        Kind::Double => quote!(#encoder.write_double(#tag, *#value)?;),
        Kind::Float => quote!(#encoder.write_float(#tag, *#value)?;),
        Kind::Int32 => quote!(#encoder.write_int32(#tag, *#value)?;),
        Kind::Int64 => quote!(#encoder.write_int64(#tag, *#value)?;),
        Kind::Uint32 => quote!(#encoder.write_varint(#tag, u64::from(*#value))?;),
        Kind::Uint64 => quote!(#encoder.write_varint(#tag, *#value)?;),
        Kind::Sint32 => quote!(#encoder.write_sint32(#tag, *#value)?;),
        Kind::Sint64 => quote!(#encoder.write_sint64(#tag, *#value)?;),
        Kind::Fixed32 => quote!(#encoder.write_fixed32(#tag, *#value)?;),
        Kind::Fixed64 => quote!(#encoder.write_fixed64(#tag, *#value)?;),
        Kind::Sfixed32 => {
            quote!(#encoder.write_fixed32(#tag, u32::from_le_bytes((*#value).to_le_bytes()))?;)
        }
        Kind::Sfixed64 => {
            quote!(#encoder.write_fixed64(#tag, u64::from_le_bytes((*#value).to_le_bytes()))?;)
        }
        Kind::Bool => quote!(#encoder.write_bool(#tag, *#value)?;),
        Kind::String => quote!(#encoder.write_string(#tag, #value.as_ref())?;),
        Kind::Bytes => quote!(#encoder.write_bytes(#tag, #value.as_ref())?;),
        Kind::Message => quote! {
            let __proto_nested =
                ::asupersync::grpc::protobuf::ProtoMessage::encode_to_bytes(
                    #value,
                    ::asupersync::grpc::protobuf::ProtobufWireLimits::default(),
                )?;
            #encoder.write_message(#tag, __proto_nested.as_ref())?;
        },
        Kind::Enumeration(path) => quote! {
            let _: ::core::marker::PhantomData<#path> = ::core::marker::PhantomData;
            #encoder.write_enum(#tag, *#value)?;
        },
        Kind::Map { .. } | Kind::Oneof | Kind::UnknownFields => {
            unreachable!("container kinds are expanded separately")
        }
    }
}

fn packed_projection(kind: &Kind, value: &TokenStream2) -> TokenStream2 {
    match kind {
        Kind::Double | Kind::Float => quote!(#value.to_bits()),
        Kind::Int32 => quote!(#value as i64 as u64),
        Kind::Int64 => quote!(#value as u64),
        Kind::Uint32 | Kind::Bool => quote!(u64::from(#value)),
        Kind::Uint64 | Kind::Fixed32 | Kind::Fixed64 => quote!(#value),
        Kind::Sint32 => {
            quote!(u64::from(::asupersync::grpc::protobuf::zigzag_encode_i32(#value)))
        }
        Kind::Sint64 => quote!(::asupersync::grpc::protobuf::zigzag_encode_i64(#value)),
        Kind::Sfixed32 => quote!(u32::from_le_bytes((#value).to_le_bytes())),
        Kind::Sfixed64 => quote!(u64::from_le_bytes((#value).to_le_bytes())),
        Kind::Enumeration(path) => quote!({
            let _: ::core::marker::PhantomData<#path> = ::core::marker::PhantomData;
            #value as i64 as u64
        }),
        _ => unreachable!("only packable kinds have a packed projection"),
    }
}

fn packed_encode(kind: &Kind, ident: &Ident, tag: u32) -> TokenStream2 {
    let projection = packed_projection(kind, &quote!(*value));
    match kind {
        Kind::Double | Kind::Fixed64 | Kind::Sfixed64 => quote! {
            if !self.#ident.is_empty() {
                let __proto_packed: ::std::vec::Vec<u64> =
                    self.#ident.iter().map(|value| #projection).collect();
                encoder.write_packed_fixed64(#tag, &__proto_packed)?;
            }
        },
        Kind::Float | Kind::Fixed32 | Kind::Sfixed32 => quote! {
            if !self.#ident.is_empty() {
                let __proto_packed: ::std::vec::Vec<u32> =
                    self.#ident.iter().map(|value| #projection).collect();
                encoder.write_packed_fixed32(#tag, &__proto_packed)?;
            }
        },
        _ => quote! {
            if !self.#ident.is_empty() {
                let __proto_packed: ::std::vec::Vec<u64> =
                    self.#ident.iter().map(|value| #projection).collect();
                encoder.write_packed_varints(#tag, &__proto_packed)?;
            }
        },
    }
}

fn encode_map(ident: &Ident, key_kind: &Kind, value_kind: &Kind, tag: u32) -> TokenStream2 {
    let key_encode = encode_call(key_kind, &quote!(__proto_entry), &quote!(__proto_key), 1);
    let value_encode = encode_call(
        value_kind,
        &quote!(__proto_entry),
        &quote!(__proto_value),
        2,
    );
    quote! {
        {
            let mut __proto_entries: ::std::vec::Vec<_> = self.#ident.iter().collect();
            __proto_entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (__proto_key, __proto_value) in __proto_entries {
                let mut __proto_entry =
                    ::asupersync::grpc::protobuf::ProtobufWireEncoder::new(
                        ::asupersync::grpc::protobuf::ProtobufWireLimits::default(),
                    );
                #key_encode
                #value_encode
                let __proto_entry = __proto_entry.finish()?;
                encoder.write_message(#tag, __proto_entry.as_ref())?;
            }
        }
    }
}

fn encode_field(spec: &FieldSpec) -> TokenStream2 {
    let ident = &spec.ident;
    let span = spec.span;
    match &spec.kind {
        Kind::UnknownFields => quote_spanned!(span=> self.#ident.encode(encoder)?;),
        Kind::Oneof => quote_spanned!(span=>
            if let ::core::option::Option::Some(value) = &self.#ident {
                ::asupersync::grpc::protobuf::ProtoOneof::encode_oneof(value, encoder)?;
            }
        ),
        Kind::Map { key, value } => {
            encode_map(ident, key, value, spec.tag.expect("validated map tag"))
        }
        kind => {
            let tag = spec.tag.expect("validated field tag");
            match spec.cardinality {
                Cardinality::Singular => {
                    let condition = default_test(kind, &quote!(self.#ident));
                    let call = encode_call(kind, &quote!(encoder), &quote!(&self.#ident), tag);
                    quote_spanned!(span=>
                        if #condition {
                            #call
                        }
                    )
                }
                Cardinality::Optional => {
                    let call = encode_call(kind, &quote!(encoder), &quote!(value), tag);
                    quote_spanned!(span=>
                        if let ::core::option::Option::Some(value) = &self.#ident {
                            #call
                        }
                    )
                }
                Cardinality::Repeated if spec.packed => packed_encode(kind, ident, tag),
                Cardinality::Repeated => {
                    let call = encode_call(kind, &quote!(encoder), &quote!(value), tag);
                    quote_spanned!(span=>
                        for value in &self.#ident {
                            #call
                        }
                    )
                }
            }
        }
    }
}

fn decode_expression(kind: &Kind, field: &TokenStream2) -> TokenStream2 {
    match kind {
        Kind::Double => quote!(f64::from_bits(#field.as_fixed64()?)),
        Kind::Float => quote!(f32::from_bits(#field.as_fixed32()?)),
        Kind::Int32 | Kind::Enumeration(_) => {
            quote!(i32::from_le_bytes((#field.as_varint()? as u32).to_le_bytes()))
        }
        Kind::Int64 => quote!(i64::from_le_bytes(#field.as_varint()?.to_le_bytes())),
        Kind::Uint32 => quote!(#field.as_varint()? as u32),
        Kind::Uint64 => quote!(#field.as_varint()?),
        Kind::Sint32 => {
            quote!(::asupersync::grpc::protobuf::zigzag_decode_i32(#field.as_varint()? as u32))
        }
        Kind::Sint64 => {
            quote!(::asupersync::grpc::protobuf::zigzag_decode_i64(#field.as_varint()?))
        }
        Kind::Fixed32 => quote!(#field.as_fixed32()?),
        Kind::Fixed64 => quote!(#field.as_fixed64()?),
        Kind::Sfixed32 => quote!(i32::from_le_bytes(#field.as_fixed32()?.to_le_bytes())),
        Kind::Sfixed64 => quote!(i64::from_le_bytes(#field.as_fixed64()?.to_le_bytes())),
        Kind::Bool => quote!(#field.as_varint()? != 0),
        Kind::String => quote!(#field.as_str()?.to_owned()),
        Kind::Bytes => quote!(#field.as_bytes()?.to_vec()),
        Kind::Message | Kind::Map { .. } | Kind::Oneof | Kind::UnknownFields => {
            unreachable!("container decode requires a target")
        }
    }
}

fn decoded_packed_value(kind: &Kind, raw: &TokenStream2) -> TokenStream2 {
    match kind {
        Kind::Double => quote!(f64::from_bits(#raw)),
        Kind::Float => quote!(f32::from_bits(#raw)),
        Kind::Int32 | Kind::Enumeration(_) => {
            quote!(i32::from_le_bytes((#raw as u32).to_le_bytes()))
        }
        Kind::Int64 | Kind::Sfixed64 => quote!(i64::from_le_bytes(#raw.to_le_bytes())),
        Kind::Uint32 => quote!(#raw as u32),
        Kind::Uint64 | Kind::Fixed32 | Kind::Fixed64 => quote!(#raw),
        Kind::Sint32 => {
            quote!(::asupersync::grpc::protobuf::zigzag_decode_i32(#raw as u32))
        }
        Kind::Sint64 => quote!(::asupersync::grpc::protobuf::zigzag_decode_i64(#raw)),
        Kind::Sfixed32 => quote!(i32::from_le_bytes(#raw.to_le_bytes())),
        Kind::Bool => quote!(#raw != 0),
        _ => unreachable!("only packable kinds decode packed values"),
    }
}

fn decode_repeated_packable(kind: &Kind, ident: &Ident) -> TokenStream2 {
    let unpacked = decode_expression(kind, &quote!(field));
    match kind {
        Kind::Double | Kind::Fixed64 | Kind::Sfixed64 => {
            let decoded = decoded_packed_value(kind, &quote!(__proto_raw));
            quote! {
                if field.wire_type() == ::asupersync::grpc::protobuf::WireType::LengthDelimited {
                    let __proto_bytes = field.as_bytes()?;
                    let mut __proto_chunks = __proto_bytes.chunks_exact(8);
                    for __proto_chunk in &mut __proto_chunks {
                        let __proto_raw = u64::from_le_bytes(
                            __proto_chunk.try_into().expect("chunks_exact guarantees eight bytes"),
                        );
                        self.#ident.push(#decoded);
                    }
                    let __proto_remainder = __proto_chunks.remainder();
                    if !__proto_remainder.is_empty() {
                        return Err(::asupersync::grpc::protobuf::ProtobufWireError::UnexpectedEof {
                            offset: field.value_offset()
                                + (__proto_bytes.len() - __proto_remainder.len()),
                            needed: 8,
                            remaining: __proto_remainder.len(),
                        });
                    }
                } else {
                    self.#ident.push(#unpacked);
                }
            }
        }
        Kind::Float | Kind::Fixed32 | Kind::Sfixed32 => {
            let decoded = decoded_packed_value(kind, &quote!(__proto_raw));
            quote! {
                if field.wire_type() == ::asupersync::grpc::protobuf::WireType::LengthDelimited {
                    let __proto_bytes = field.as_bytes()?;
                    let mut __proto_chunks = __proto_bytes.chunks_exact(4);
                    for __proto_chunk in &mut __proto_chunks {
                        let __proto_raw = u32::from_le_bytes(
                            __proto_chunk.try_into().expect("chunks_exact guarantees four bytes"),
                        );
                        self.#ident.push(#decoded);
                    }
                    let __proto_remainder = __proto_chunks.remainder();
                    if !__proto_remainder.is_empty() {
                        return Err(::asupersync::grpc::protobuf::ProtobufWireError::UnexpectedEof {
                            offset: field.value_offset()
                                + (__proto_bytes.len() - __proto_remainder.len()),
                            needed: 4,
                            remaining: __proto_remainder.len(),
                        });
                    }
                } else {
                    self.#ident.push(#unpacked);
                }
            }
        }
        _ => {
            let decoded = decoded_packed_value(kind, &quote!(__proto_raw));
            quote! {
                if field.wire_type() == ::asupersync::grpc::protobuf::WireType::LengthDelimited {
                    let mut __proto_bytes = field.as_bytes()?;
                    while !__proto_bytes.is_empty() {
                        let (__proto_raw, __proto_consumed) =
                            ::asupersync::grpc::protobuf::decode_varint(__proto_bytes)?;
                        self.#ident.push(#decoded);
                        __proto_bytes = &__proto_bytes[__proto_consumed..];
                    }
                } else {
                    self.#ident.push(#unpacked);
                }
            }
        }
    }
}

fn decode_map(
    ident: &Ident,
    ty: &Type,
    key_kind: &Kind,
    value_kind: &Kind,
) -> Result<TokenStream2> {
    let (key_ty, value_ty) = map_type_arguments(ty, ty.span())?;
    let key_decode = decode_expression(key_kind, &quote!(__proto_entry_field));
    let value_decode = if matches!(value_kind, Kind::Message) {
        quote! {
            ::asupersync::grpc::protobuf::merge_nested_message(
                &mut __proto_value,
                &__proto_entry_field,
                &mut __proto_entry_decoder,
            )?;
        }
    } else {
        let expression = decode_expression(value_kind, &quote!(__proto_entry_field));
        quote!(__proto_value = #expression;)
    };
    Ok(quote! {
        {
            let mut __proto_key: #key_ty = ::core::default::Default::default();
            let mut __proto_value: #value_ty = ::core::default::Default::default();
            let mut __proto_entry_decoder = decoder.nested_message(field)?;
            while let ::core::option::Option::Some(__proto_entry_field) =
                __proto_entry_decoder.next_field()?
            {
                match __proto_entry_field.field_number() {
                    1 => {
                        __proto_key = #key_decode;
                    }
                    2 => {
                        #value_decode
                    }
                    _ => {
                        if __proto_entry_field.wire_type()
                            == ::asupersync::grpc::protobuf::WireType::StartGroup
                        {
                            __proto_entry_decoder.skip_group(&__proto_entry_field)?;
                        }
                    }
                }
            }
            self.#ident.insert(__proto_key, __proto_value);
        }
    })
}

fn decode_field(spec: &FieldSpec) -> Result<TokenStream2> {
    let ident = &spec.ident;
    let span = spec.span;
    match &spec.kind {
        Kind::UnknownFields => Ok(TokenStream2::new()),
        Kind::Oneof => {
            let oneof_ty = single_type_argument(&spec.ty, "Option", span)?;
            let tags = &spec.oneof_tags;
            let arms = tags.iter().map(|tag| {
                quote_spanned!(span=>
                    #tag => {
                        if let ::core::option::Option::Some(value) =
                            <#oneof_ty as ::asupersync::grpc::protobuf::ProtoOneof>::decode_oneof(
                                field,
                                decoder,
                            )?
                        {
                            self.#ident = ::core::option::Option::Some(value);
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    },
                )
            });
            Ok(quote!(#(#arms)*))
        }
        Kind::Map { key, value } => {
            let tag = spec.tag.expect("validated map tag");
            let body = decode_map(ident, &spec.ty, key, value)?;
            Ok(quote_spanned!(span=>
                #tag => {
                    #body
                    Ok(true)
                },
            ))
        }
        kind => {
            let tag = spec.tag.expect("validated field tag");
            let body = match (spec.cardinality, kind) {
                (Cardinality::Singular, Kind::Message) => quote! {
                    ::asupersync::grpc::protobuf::merge_nested_message(
                        &mut self.#ident,
                        field,
                        decoder,
                    )?;
                },
                (Cardinality::Optional, Kind::Message) => {
                    let inner = single_type_argument(&spec.ty, "Option", span)?;
                    quote! {
                        let mut __proto_nested: #inner =
                            self.#ident.take().unwrap_or_default();
                        ::asupersync::grpc::protobuf::merge_nested_message(
                            &mut __proto_nested,
                            field,
                            decoder,
                        )?;
                        self.#ident = ::core::option::Option::Some(__proto_nested);
                    }
                }
                (Cardinality::Repeated, Kind::Message) => {
                    let inner = single_type_argument(&spec.ty, "Vec", span)?;
                    quote! {
                        let mut __proto_nested: #inner = ::core::default::Default::default();
                        ::asupersync::grpc::protobuf::merge_nested_message(
                            &mut __proto_nested,
                            field,
                            decoder,
                        )?;
                        self.#ident.push(__proto_nested);
                    }
                }
                (Cardinality::Repeated, packable) if packable.is_packable() => {
                    decode_repeated_packable(packable, ident)
                }
                (Cardinality::Singular, scalar) => {
                    let expression = decode_expression(scalar, &quote!(field));
                    quote!(self.#ident = #expression;)
                }
                (Cardinality::Optional, scalar) => {
                    let expression = decode_expression(scalar, &quote!(field));
                    quote!(self.#ident = ::core::option::Option::Some(#expression);)
                }
                (Cardinality::Repeated, scalar) => {
                    let expression = decode_expression(scalar, &quote!(field));
                    quote!(self.#ident.push(#expression);)
                }
            };
            Ok(quote_spanned!(span=>
                #tag => {
                    #body
                    Ok(true)
                },
            ))
        }
    }
}

fn oneof_tag_assertion(spec: &FieldSpec) -> Result<TokenStream2> {
    if !matches!(spec.kind, Kind::Oneof) {
        return Ok(TokenStream2::new());
    }
    let oneof_ty = single_type_argument(&spec.ty, "Option", spec.span)?;
    let tags = &spec.oneof_tags;
    let count = tags.len();
    Ok(quote_spanned!(spec.span=>
        const _: () = {
            let declared: &[u32] = &[#(#tags),*];
            let actual =
                <#oneof_ty as ::asupersync::grpc::protobuf::ProtoOneof>::FIELD_NUMBERS;
            if actual.len() != #count {
                panic!("oneof `tags` list does not match the derived oneof variants");
            }
            let mut index = 0usize;
            while index < #count {
                if actual[index] != declared[index] {
                    panic!("oneof `tags` list does not match the derived oneof variants");
                }
                index += 1;
            };
        };
    ))
}

pub fn derive_proto_message(input: &DeriveInput) -> Result<TokenStream2> {
    let name = &input.ident;
    let Data::Struct(data) = &input.data else {
        return Err(Error::new(
            input.span(),
            "ProtoMessage can be derived only for a struct",
        ));
    };
    let mut specs = parse_struct_fields(data)?;
    let assertions = specs
        .iter()
        .map(oneof_tag_assertion)
        .collect::<Result<Vec<_>>>()?;

    specs.sort_by_key(|spec| {
        spec.tag
            .or_else(|| spec.oneof_tags.first().copied())
            .unwrap_or(u32::MAX)
    });
    let encode_fields = specs.iter().map(encode_field).collect::<Vec<_>>();
    let decode_arms = specs
        .iter()
        .filter(|spec| !matches!(spec.kind, Kind::UnknownFields))
        .map(decode_field)
        .collect::<Result<Vec<_>>>()?;
    let unknown = specs
        .iter()
        .find(|spec| matches!(spec.kind, Kind::UnknownFields))
        .map_or_else(
            || quote!(Ok(false)),
            |spec| {
                let ident = &spec.ident;
                quote! {
                    {
                        if field.wire_type()
                            == ::asupersync::grpc::protobuf::WireType::StartGroup
                        {
                            self.#ident.record_group(field, decoder)?;
                        } else {
                            self.#ident.record(field);
                        }
                        Ok(true)
                    }
                }
            },
        );

    let generics = &input.generics;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    Ok(quote! {
        #(#assertions)*

        impl #impl_generics ::asupersync::grpc::protobuf::ProtoMessage
            for #name #type_generics #where_clause
        {
            fn encode_fields(
                &self,
                encoder: &mut ::asupersync::grpc::protobuf::ProtobufWireEncoder,
            ) -> ::core::result::Result<
                (),
                ::asupersync::grpc::protobuf::ProtobufWireError,
            > {
                #(#encode_fields)*
                Ok(())
            }

            fn merge_field<'wire>(
                &mut self,
                field: &::asupersync::grpc::protobuf::ProtobufWireField<'wire>,
                decoder: &mut ::asupersync::grpc::protobuf::ProtobufWireDecoder<'wire, '_>,
            ) -> ::core::result::Result<
                bool,
                ::asupersync::grpc::protobuf::ProtobufWireError,
            > {
                match field.field_number() {
                    #(#decode_arms)*
                    _ => #unknown,
                }
            }
        }
    })
}

fn parse_oneof_variant(variant: &Variant) -> Result<(Ident, Type, Kind, u32)> {
    let parsed = parse_proto_attribute(proto_attribute(&variant.attrs)?)?;
    let kind = parsed
        .kind
        .ok_or_else(|| Error::new(variant.span(), "missing protobuf wire kind"))?;
    if matches!(kind, Kind::Map { .. } | Kind::Oneof | Kind::UnknownFields)
        || parsed.cardinality != Cardinality::Singular
        || parsed.packed
        || !parsed.oneof_tags.is_empty()
    {
        return Err(Error::new(
            variant.span(),
            "oneof variants require one scalar, string, bytes, message, or enumeration kind and one tag",
        ));
    }
    let tag = parsed
        .tag
        .ok_or_else(|| Error::new(variant.span(), "oneof variant is missing `tag = N`"))?;
    validate_tag(tag, variant.span())?;
    let Fields::Unnamed(fields) = &variant.fields else {
        return Err(Error::new(
            variant.fields.span(),
            "oneof variants must be tuple variants with exactly one value",
        ));
    };
    if fields.unnamed.len() != 1 {
        return Err(Error::new(
            fields.span(),
            "oneof variants must contain exactly one value",
        ));
    }
    let ty = fields.unnamed.first().expect("length checked").ty.clone();
    Ok((variant.ident.clone(), ty, kind, tag))
}

fn derive_oneof_data(
    name: &Ident,
    data: &DataEnum,
) -> Result<(Vec<TokenStream2>, Vec<TokenStream2>, Vec<u32>)> {
    let mut variants = Vec::with_capacity(data.variants.len());
    let mut tags = BTreeMap::<u32, Span>::new();
    for variant in &data.variants {
        let parsed = parse_oneof_variant(variant)?;
        if tags.insert(parsed.3, variant.span()).is_some() {
            return Err(Error::new(
                variant.span(),
                format!("protobuf oneof tag {} is declared more than once", parsed.3),
            ));
        }
        variants.push(parsed);
    }
    variants.sort_by_key(|variant| variant.3);

    let encode = variants
        .iter()
        .map(|(variant, _, kind, tag)| {
            let call = encode_call(kind, &quote!(encoder), &quote!(value), *tag);
            quote!(Self::#variant(value) => { #call })
        })
        .collect();
    let decode = variants
        .iter()
        .map(|(variant, ty, kind, tag)| {
            let body = if matches!(kind, Kind::Message) {
                quote! {
                    let mut value: #ty = ::core::default::Default::default();
                    ::asupersync::grpc::protobuf::merge_nested_message(
                        &mut value,
                        field,
                        decoder,
                    )?;
                    value
                }
            } else {
                decode_expression(kind, &quote!(field))
            };
            quote!(#tag => Ok(::core::option::Option::Some(Self::#variant({ #body }))))
        })
        .collect();
    let tag_values = variants.iter().map(|variant| variant.3).collect();
    let _ = name;
    Ok((encode, decode, tag_values))
}

pub fn derive_proto_oneof(input: &DeriveInput) -> Result<TokenStream2> {
    let name = &input.ident;
    let Data::Enum(data) = &input.data else {
        return Err(Error::new(
            input.span(),
            "ProtoOneof can be derived only for an enum",
        ));
    };
    let (encode_arms, decode_arms, tags) = derive_oneof_data(name, data)?;
    if tags.is_empty() {
        return Err(Error::new(
            input.span(),
            "ProtoOneof requires at least one variant",
        ));
    }

    let generics = &input.generics;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics ::asupersync::grpc::protobuf::ProtoOneof
            for #name #type_generics #where_clause
        {
            const FIELD_NUMBERS: &'static [u32] = &[#(#tags),*];

            fn encode_oneof(
                &self,
                encoder: &mut ::asupersync::grpc::protobuf::ProtobufWireEncoder,
            ) -> ::core::result::Result<
                (),
                ::asupersync::grpc::protobuf::ProtobufWireError,
            > {
                match self {
                    #(#encode_arms,)*
                }
                Ok(())
            }

            fn decode_oneof<'wire>(
                field: &::asupersync::grpc::protobuf::ProtobufWireField<'wire>,
                decoder: &mut ::asupersync::grpc::protobuf::ProtobufWireDecoder<'wire, '_>,
            ) -> ::core::result::Result<
                ::core::option::Option<Self>,
                ::asupersync::grpc::protobuf::ProtobufWireError,
            > {
                match field.field_number() {
                    #(#decode_arms,)*
                    _ => Ok(::core::option::Option::None),
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{derive_proto_message, derive_proto_oneof};
    use syn::{DeriveInput, parse_quote};

    const fn fnv1a(bytes: &[u8]) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325;
        let mut index = 0;
        while index < bytes.len() {
            hash ^= bytes[index] as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            index += 1;
        }
        hash
    }

    #[test]
    fn proto_message_expansion_golden() {
        let input: DeriveInput = parse_quote! {
            struct GoldenMessage {
                #[proto(string, tag = 1)]
                name: String,
                #[proto(uint64, repeated, packed, tag = 2)]
                values: Vec<u64>,
                #[proto(unknown_fields)]
                unknown: UnknownFields,
            }
        };
        let first = derive_proto_message(&input)
            .expect("valid message")
            .to_string();
        let second = derive_proto_message(&input)
            .expect("valid message")
            .to_string();
        assert_eq!(first, second, "the same schema must expand byte-for-byte");
        assert_eq!(fnv1a(first.as_bytes()), 14_716_714_724_283_674_067);
    }

    #[test]
    fn proto_oneof_expansion_golden() {
        let input: DeriveInput = parse_quote! {
            enum GoldenOneof {
                #[proto(string, tag = 4)]
                Text(String),
                #[proto(uint64, tag = 5)]
                Sequence(u64),
            }
        };
        let first = derive_proto_oneof(&input).expect("valid oneof").to_string();
        let second = derive_proto_oneof(&input).expect("valid oneof").to_string();
        assert_eq!(first, second, "the same oneof must expand byte-for-byte");
        assert_eq!(fnv1a(first.as_bytes()), 16_917_859_845_603_613_625);
    }
}
