//! PostgreSQL one-dimensional arrays through the public `ToSql` / `FromSql`
//! codecs, without a server: `Vec<T>` binds as PostgreSQL's binary array
//! format and decodes from both the text output (`{1,"a b",NULL}`) and the
//! binary format. `tests/postgres_real_server.rs` round-trips the same values
//! through a real server.
#![cfg(feature = "postgres")]

use asupersync::database::postgres::{Format, FromSql, IsNull, ToSql, oid};

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
