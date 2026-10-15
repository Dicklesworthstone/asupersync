//! PostgreSQL one-dimensional arrays through the public `ToSql` / `FromSql`
//! codecs, without a server: `Vec<T>` binds as PostgreSQL's binary array
//! format and decodes from both the text output (`{1,"a b",NULL}`) and the
//! binary format. `tests/postgres_real_server.rs` round-trips the same values
//! through a real server.
#![cfg(feature = "postgres")]

use asupersync::database::postgres::{
    Format, FromSql, IsNull, PgArrayElement, PgError, ToSql, oid,
};

fn encode(value: &dyn ToSql) -> Vec<u8> {
    let mut buf = Vec::new();
    assert_eq!(value.to_sql(&mut buf).expect("encode"), IsNull::No);
    buf
}

fn be(values: &[i32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

#[test]
fn arrays_bind_in_binary_array_format_with_the_array_type_oid() {
    let ids = vec![7_i32, -1];
    assert_eq!(ids.type_oid(), oid::INT4_ARRAY);
    assert_eq!(ids.format(), Format::Binary);
    let mut expected = be(&[1, 0, oid::INT4.cast_signed(), 2, 1]);
    expected.extend(be(&[4, 7, 4, -1]));
    assert_eq!(encode(&ids), expected);

    // A NULL element sets the has-NULL flag and is written as length -1.
    let names = vec![Some("ab"), None];
    assert_eq!(names.type_oid(), oid::TEXT_ARRAY);
    let mut expected = be(&[1, 1, oid::TEXT.cast_signed(), 2, 1, 2]);
    expected.extend_from_slice(b"ab");
    expected.extend(be(&[-1]));
    assert_eq!(encode(&names), expected);

    // An empty array has no dimensions.
    let empty: Vec<i64> = Vec::new();
    assert_eq!(empty.type_oid(), oid::INT8_ARRAY);
    assert_eq!(encode(&empty), be(&[0, 0, oid::INT8.cast_signed()]));

    // Slices bind too, and bytea elements keep their bytes.
    let blobs: &[Vec<u8>] = &[vec![0, 255]];
    assert_eq!(blobs.type_oid(), oid::BYTEA_ARRAY);
    // A plain Vec<u8> is still a bytea value, not an array.
    assert_eq!(vec![1_u8, 2].type_oid(), oid::BYTEA);
}

#[test]
fn arrays_decode_from_text_output() {
    let ints = Vec::<i32>::from_sql(b"{1,-2,3}", oid::INT4_ARRAY, Format::Text).unwrap();
    assert_eq!(ints, [1, -2, 3]);

    let text = br#"{plain,"a b","q\"u","back\\slash","",NULL,"NULL","{x,y}"}"#;
    let strings = Vec::<Option<String>>::from_sql(text, oid::TEXT_ARRAY, Format::Text).unwrap();
    assert_eq!(
        strings,
        [
            Some("plain".to_string()),
            Some("a b".to_string()),
            Some("q\"u".to_string()),
            Some("back\\slash".to_string()),
            Some(String::new()),
            None,
            Some("NULL".to_string()),
            Some("{x,y}".to_string()),
        ]
    );

    let empty = Vec::<i64>::from_sql(b"{}", oid::INT8_ARRAY, Format::Text).unwrap();
    assert!(empty.is_empty());
    // Non-default bounds prefix the braces.
    let shifted = Vec::<i16>::from_sql(b"[0:1]={5,6}", oid::INT2_ARRAY, Format::Text).unwrap();
    assert_eq!(shifted, [5, 6]);
    let flags = Vec::<bool>::from_sql(b"{t,f}", oid::BOOL_ARRAY, Format::Text).unwrap();
    assert_eq!(flags, [true, false]);
    let blobs =
        Vec::<Vec<u8>>::from_sql(br#"{"\\x00ff"}"#, oid::BYTEA_ARRAY, Format::Text).unwrap();
    assert_eq!(blobs, [vec![0, 255]]);

    // A NULL element needs an Option element type.
    assert!(Vec::<i32>::from_sql(b"{1,NULL}", oid::INT4_ARRAY, Format::Text).is_err());
    // One dimension only, and the array type must be known.
    assert!(Vec::<i32>::from_sql(b"{{1,2},{3,4}}", oid::INT4_ARRAY, Format::Text).is_err());
    assert!(
        Vec::<i32>::from_sql(b"[1:2][1:2]={{1,2},{3,4}}", oid::INT4_ARRAY, Format::Text).is_err()
    );
    assert!(Vec::<i32>::from_sql(b"{1,2}", oid::INT4, Format::Text).is_err());
    assert!(Vec::<i32>::from_sql(b"{1,2", oid::INT4_ARRAY, Format::Text).is_err());
    assert!(Vec::<String>::from_sql(br#"{"open}"#, oid::TEXT_ARRAY, Format::Text).is_err());

    assert!(<Vec<i64> as FromSql>::accepts(oid::INT8_ARRAY));
    assert!(<Vec<String> as FromSql>::accepts(oid::UUID_ARRAY));
    assert!(!<Vec<i64> as FromSql>::accepts(oid::INT8));
}

#[test]
fn arrays_round_trip_through_the_binary_format() {
    let values = vec![Some(3.5_f64), None, Some(-0.25)];
    let bytes = encode(&values);
    let decoded = Vec::<Option<f64>>::from_sql(&bytes, oid::FLOAT8_ARRAY, Format::Binary).unwrap();
    assert_eq!(decoded, values);

    let empty: Vec<bool> = Vec::new();
    let decoded = Vec::<bool>::from_sql(&encode(&empty), oid::BOOL_ARRAY, Format::Binary).unwrap();
    assert!(decoded.is_empty());

    // Truncated, mistyped and trailing input is refused.
    let bytes = encode(&vec![1_i32, 2]);
    assert!(
        Vec::<i32>::from_sql(&bytes[..bytes.len() - 1], oid::INT4_ARRAY, Format::Binary).is_err()
    );
    assert!(Vec::<i32>::from_sql(&bytes, oid::INT8_ARRAY, Format::Binary).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Vec::<i32>::from_sql(&trailing, oid::INT4_ARRAY, Format::Binary).is_err());
}

/// A downstream id type whose `ToSql` sends the decimal text, which is valid
/// for a scalar `int4` parameter (`Format::Text`).
struct UserId(i32);

impl ToSql for UserId {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(self.0.to_string().as_bytes());
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::INT4
    }
    fn format(&self) -> Format {
        Format::Text
    }
}

impl PgArrayElement for UserId {
    const ARRAY_OID: u32 = oid::INT4_ARRAY;
    const ELEMENT_OID: u32 = oid::INT4;
}

/// A downstream `name` (system identifier) type whose `ToSql` sends its text,
/// which is also the binary form of `name`.
struct Ident(&'static str);

impl ToSql for Ident {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(self.0.as_bytes());
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::NAME
    }
    fn format(&self) -> Format {
        Format::Text
    }
}

impl PgArrayElement for Ident {
    const ARRAY_OID: u32 = oid::NAME_ARRAY;
    const ELEMENT_OID: u32 = oid::NAME;
}

/// qml5yb review follow-up: `name`'s binary form is its text (`namerecv`
/// reads the identifier's text, as `textrecv` does). So a text-encoding
/// `name` element binds inside a binary `name[]`, and a `name[]` result
/// decodes into `Vec<String>`. Before, the bind refused the element as a
/// text encoding, and `name[]` was not a known array type.
#[test]
fn a_name_array_binds_its_text_elements_and_decodes_as_strings() {
    let mut expected = be(&[1, 0, oid::NAME.cast_signed(), 2, 1, 7]);
    expected.extend_from_slice(b"pg_proc");
    expected.extend(be(&[8]));
    expected.extend_from_slice(b"pg_class");
    assert_eq!(encode(&vec![Ident("pg_proc"), Ident("pg_class")]), expected);
    assert_eq!(
        Vec::<String>::from_sql(b"{pg_proc,pg_class}", oid::NAME_ARRAY, Format::Text)
            .expect("name[] text output"),
        ["pg_proc", "pg_class"]
    );
    assert_eq!(
        Vec::<String>::from_sql(&expected, oid::NAME_ARRAY, Format::Binary)
            .expect("name[] binary output"),
        ["pg_proc", "pg_class"]
    );
}

/// asupersync-qml5yb finding 6: arrays are sent in binary format, so a
/// text-encoding element was copied in as is and the server read `b"1234"`
/// as the int4 825373492: a wrong id stored or matched, with no error. Such
/// an element is now refused; text types, whose text is their binary form,
/// still bind.
#[test]
fn a_binary_array_refuses_an_element_that_encodes_itself_as_text() {
    let mut buf = Vec::new();
    let error = vec![UserId(1234)]
        .to_sql(&mut buf)
        .expect_err("a text-encoded int4 inside a binary int4[]");
    assert!(error.to_string().contains("encodes as text"), "{error}");
    // A NULL element has no bytes to check.
    let nulls: Vec<Option<UserId>> = vec![None];
    assert_eq!(
        encode(&nulls),
        be(&[1, 1, oid::INT4.cast_signed(), 1, 1, -1])
    );

    let mut expected = be(&[1, 0, oid::TEXT.cast_signed(), 1, 1, 1]);
    expected.push(b'a');
    assert_eq!(encode(&vec!["a".to_owned()]), expected);
    assert_eq!(encode(&vec!["a"]), expected);
}
