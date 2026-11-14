//! PostgreSQL arrays through the public `ToSql` / `FromSql` codecs, without a
//! server. `Vec<T>` retains its one-dimensional behavior; `PgArray<T>` preserves
//! rectangular shapes and SQL lower bounds. Both bind in binary and decode
//! text or binary results. `tests/postgres_real_server.rs` exercises their
//! parameter, prepared-statement, and result paths against a real server.
#![cfg(feature = "postgres")]

use asupersync::database::postgres::{
    Format, FromSql, IsNull, PgArray, PgArrayDimension, PgArrayElement, PgError, ToSql, oid,
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

fn dimension(length: usize, lower: i32) -> PgArrayDimension {
    PgArrayDimension::new(length, lower).expect("valid dimension")
}

#[test]
fn shaped_arrays_preserve_two_dimensions_bounds_and_null_elements() {
    let values = PgArray::new(
        vec![dimension(2, 0), dimension(2, -1)],
        vec![Some(1_i32), None, Some(3), Some(4)],
    )
    .unwrap();
    let mut expected = be(&[2, 1, oid::INT4.cast_signed(), 2, 0, 2, -1]);
    expected.extend(be(&[4, 1, -1, 4, 3, 4, 4]));
    assert_eq!(values.type_oid(), oid::INT4_ARRAY);
    assert_eq!(values.format(), Format::Binary);
    assert_eq!(encode(&values), expected);
    let binary =
        PgArray::<Option<i32>>::from_sql(&expected, oid::INT4_ARRAY, Format::Binary).unwrap();
    let text = PgArray::<Option<i32>>::from_sql(
        b"[0:1][-1:0]={{1,NULL},{3,4}}",
        oid::INT4_ARRAY,
        Format::Text,
    )
    .unwrap();
    assert_eq!(binary, values);
    assert_eq!(text, values);
    assert_eq!(values.get(&[0, 0]), Some(&None));
    assert_eq!(values.get(&[1, -1]), Some(&Some(3)));
    assert_eq!(values.dimensions()[0].lower_bound(), 0);
    assert_eq!(values.dimensions()[0].upper_bound(), 1);
    assert_eq!(values.dimensions()[1].length(), 2);
    // The established Vec API still refuses multidimensional input.
    assert!(Vec::<Option<i32>>::from_sql(&expected, oid::INT4_ARRAY, Format::Binary).is_err());
    assert!(
        Vec::<Option<i32>>::from_sql(b"{{1,NULL},{3,4}}", oid::INT4_ARRAY, Format::Text).is_err()
    );
}

#[test]
fn shaped_arrays_index_three_dimensions_in_row_major_order() {
    let mut values = PgArray::new(
        vec![dimension(2, -2), dimension(2, 0), dimension(2, 5)],
        (0_i32..8).collect(),
    )
    .unwrap();
    let decoded = PgArray::<i32>::from_sql(
        b" [ -2 : -1 ][0:1][5:6] = {{{0,1},{2,3}},{{4,5},{6,7}}} ",
        oid::INT4_ARRAY,
        Format::Text,
    )
    .unwrap();
    assert_eq!(decoded, values);
    assert_eq!(values.rank(), 3);
    assert_eq!(values.len(), 8);
    assert!(!values.is_empty());
    assert_eq!(values.get(&[-1, 0, 6]), Some(&5));
    for indexes in [&[-3, 0, 5][..], &[-1, 2, 5], &[-1, 0], &[-1, 0, 5, 1]] {
        assert_eq!(values.get(indexes), None);
    }
    *values.get_mut(&[-1, 1, 6]).unwrap() = 70;
    values.elements_mut()[0] = -10;
    assert_eq!(
        PgArray::<i32>::from_sql(&encode(&values), oid::INT4_ARRAY, Format::Binary).unwrap(),
        values
    );
    let (dimensions, elements) = values.into_parts();
    assert_eq!(
        dimensions,
        [dimension(2, -2), dimension(2, 0), dimension(2, 5)]
    );
    assert_eq!(elements, [-10, 1, 2, 3, 4, 5, 6, 70]);
}

#[test]
fn shaped_arrays_parse_escaped_text_without_confusing_null_or_array_syntax() {
    let text = br#"[0:1][-1:1]={{"NULL",NULL,""},{a\,b, N\ULL, "q\"\\x"}}"#;
    let array = PgArray::<Option<String>>::from_sql(text, oid::TEXT_ARRAY, Format::Text).unwrap();
    assert_eq!(array.dimensions(), [dimension(2, 0), dimension(3, -1)]);
    assert_eq!(
        array.elements(),
        &[
            Some("NULL".into()),
            None,
            Some(String::new()),
            Some("a,b".into()),
            Some("NULL".into()),
            Some("q\"\\x".into()),
        ]
    );
    assert_eq!(
        PgArray::<Option<String>>::from_sql(&encode(&array), oid::TEXT_ARRAY, Format::Binary)
            .unwrap(),
        array
    );
    let spaced = PgArray::<String>::from_sql(
        br#"{  plain words  ,"  quoted  ",\ leading,trailing\ }"#,
        oid::TEXT_ARRAY,
        Format::Text,
    )
    .unwrap();
    assert_eq!(
        spaced.elements(),
        ["plain words", "  quoted  ", " leading", "trailing "]
    );
}

#[test]
fn shaped_arrays_distinguish_empty_arrays_null_arrays_and_null_elements() {
    let empty = PgArray::<i32>::empty();
    assert_eq!(empty.rank(), 0);
    assert_eq!(empty.get(&[]), None);
    assert_eq!(encode(&empty), be(&[0, 0, oid::INT4.cast_signed()]));
    assert_eq!(PgArray::from_vec(Vec::<i32>::new()).unwrap(), empty);
    assert_eq!(PgArray::new(Vec::new(), Vec::<i32>::new()).unwrap(), empty);
    assert_eq!(
        PgArray::<i32>::from_sql(b" { } ", oid::INT4_ARRAY, Format::Text).unwrap(),
        empty
    );
    assert_eq!(
        PgArray::<i32>::from_sql(&encode(&empty), oid::INT4_ARRAY, Format::Binary).unwrap(),
        empty
    );
    assert!(PgArray::<i32>::from_sql_null().is_err());
    assert_eq!(Option::<PgArray<i32>>::from_sql_null().unwrap(), None);
    let null = PgArray::from_vec(vec![None::<i32>]).unwrap();
    assert_eq!(null.rank(), 1);
    assert_eq!(null.len(), 1);
    assert_eq!(
        PgArray::<Option<i32>>::from_sql(b"{NULL}", oid::INT4_ARRAY, Format::Text).unwrap(),
        null
    );
    assert!(PgArray::<i32>::from_sql(&encode(&null), oid::INT4_ARRAY, Format::Binary).is_err());
}

#[test]
fn shaped_array_construction_checks_rank_bounds_and_wire_size_without_allocating_values() {
    assert!(PgArrayDimension::new(0, 1).is_err());
    assert!(PgArrayDimension::new(usize::MAX, 1).is_err());
    assert!(PgArrayDimension::new(1, i32::MAX).is_err());
    assert!(PgArrayDimension::new(2, i32::MAX - 1).is_err());
    assert_eq!(dimension(1, i32::MIN).upper_bound(), i32::MIN);
    assert_eq!(dimension(1, i32::MAX - 1).upper_bound(), i32::MAX - 1);
    assert!(PgArray::new(Vec::new(), vec![1_i32]).is_err());
    assert!(PgArray::new(vec![dimension(2, 1), dimension(2, 1)], vec![1_i32; 3]).is_err());
    assert!(PgArray::new(vec![dimension(1, 1); 7], vec![1_i32]).is_err());
    assert!(PgArray::new(vec![dimension(50_000, 1); 2], Vec::<i32>::new()).is_err());
    assert!(PgArray::new(vec![dimension(i32::MAX as usize, -1); 6], Vec::<i32>::new()).is_err());
    let six = PgArray::new(vec![dimension(1, 1); 6], vec![9_i32]).unwrap();
    assert_eq!(
        PgArray::<i32>::from_sql(b"{{{{{{9}}}}}}", oid::INT4_ARRAY, Format::Text).unwrap(),
        six
    );
    assert_eq!(
        PgArray::<i32>::from_sql(&encode(&six), oid::INT4_ARRAY, Format::Binary).unwrap(),
        six
    );
}

// A malformed outer frame/shape must be rejected before invoking downstream
// element decoders, which may allocate or perform their own side effects.
#[derive(Debug)]
struct UnreachableArrayDecoder;

impl FromSql for UnreachableArrayDecoder {
    fn from_sql(_: &[u8], _: u32, _: Format) -> Result<Self, PgError> {
        panic!("malformed array reached the element decoder")
    }
    fn from_sql_null() -> Result<Self, PgError> {
        panic!("malformed array reached the NULL decoder")
    }
    fn accepts(_: u32) -> bool {
        true
    }
}

#[test]
fn shaped_arrays_reject_malformed_text_before_decoding_elements() {
    let malformed: &[&[u8]] = &[
        b"{{1,2},{3}}",
        b"{1,{2}}",
        b"{{1},2}",
        b"{{1}{2}}",
        b"{{}}",
        b"[1:2][1:2]={{1,2},{3}}",
        b"[1:2]={1}",
        b"[1:1][1:1]={1}",
        b"[2:1]={}",
        b"[2147483647:2147483647]={1}",
        b"[0:2147483647]={1}",
        b"[1:2]{1,2}",
        b"[x:2]={1,2}",
        b"[1:2]={1,2}tail",
        b"{1,}",
        b"{,1}",
        b"{1,,2}",
        b"{1}x",
        b"{\"a\"b}",
        b"{a\\",
        b"{a\0}",
        b"{{{{{{{1}}}}}}}",
        b"{1,2",
        b"\"1\"",
        b"",
    ];
    for &text in malformed {
        assert!(
            PgArray::<UnreachableArrayDecoder>::from_sql(text, oid::INT4_ARRAY, Format::Text)
                .is_err(),
            "{text:?}"
        );
    }
}

#[test]
fn shaped_arrays_reject_malformed_binary_before_decoding_elements() {
    let valid = encode(&PgArray::from_vec(vec![7_i32]).unwrap());
    for length in 0..valid.len() {
        assert!(
            PgArray::<UnreachableArrayDecoder>::from_sql(
                &valid[..length],
                oid::INT4_ARRAY,
                Format::Binary
            )
            .is_err(),
            "truncation at {length}"
        );
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    let cases = [
        be(&[-1, 0, 23]),
        be(&[7, 0, 23]),
        be(&[0, 2, 23]),
        be(&[0, 0, 20]),
        be(&[1, 0, 23, -1, 1]),
        be(&[1, 0, 23, 0, 1]),
        be(&[1, 0, 23, 1, i32::MAX, 4, 7]),
        be(&[1, 0, 23, i32::MAX, -1]),
        be(&[2, 0, 23, i32::MAX, -1, i32::MAX, -1]),
        be(&[1, 0, 23, 1, 1, -2]),
        be(&[1, 0, 23, 1, 1, -1]),
        be(&[1, 0, 23, 1, 1, i32::MAX]),
        be(&[1, 0, 23, 1, 1, 8, 7, 8]),
        trailing,
    ];
    for bytes in cases {
        assert!(
            PgArray::<UnreachableArrayDecoder>::from_sql(&bytes, oid::INT4_ARRAY, Format::Binary)
                .is_err(),
            "{bytes:?}"
        );
    }
    assert!(PgArray::<i32>::from_sql(&valid, oid::INT4, Format::Binary).is_err());
    assert!(PgArray::<i64>::from_sql(&valid, oid::INT4_ARRAY, Format::Binary).is_err());
    assert!(!PgArray::<i32>::accepts(oid::INT4));
    assert!(PgArray::<i32>::accepts(oid::INT4_ARRAY));
}

#[test]
fn shaped_array_encode_errors_preserve_the_output_prefix() {
    let values = PgArray::new(vec![dimension(1, 0)], vec![UserId(1234)]).unwrap();
    let mut output = vec![0xaa, 0xbb];
    assert!(values.to_sql(&mut output).is_err());
    assert_eq!(output, [0xaa, 0xbb]);
    let nulls = PgArray::from_vec(vec![None::<UserId>]).unwrap();
    assert_eq!(
        encode(&nulls),
        be(&[1, 1, oid::INT4.cast_signed(), 1, 1, -1])
    );
    let names = PgArray::new(
        vec![dimension(1, 0), dimension(2, -1)],
        vec![Ident("pg_proc"), Ident("pg_class")],
    )
    .unwrap();
    let decoded =
        PgArray::<String>::from_sql(&encode(&names), oid::NAME_ARRAY, Format::Binary).unwrap();
    assert_eq!(decoded.dimensions(), [dimension(1, 0), dimension(2, -1)]);
    assert_eq!(decoded.elements(), ["pg_proc", "pg_class"]);
}

#[test]
fn shaped_text_family_arrays_are_accepted_by_typed_row_decoders() {
    assert!(String::accepts(oid::NAME));
    assert!(String::accepts(oid::BPCHAR));
    for array_oid in [oid::NAME_ARRAY, oid::BPCHAR_ARRAY, oid::VARCHAR_ARRAY] {
        assert!(PgArray::<String>::accepts(array_oid));
        let mut wire = be(&[
            1,
            0,
            oid::array_element(array_oid).unwrap().cast_signed(),
            1,
            -2,
            3,
        ]);
        wire.extend_from_slice(b"ab ");
        let binary = PgArray::<String>::from_sql(&wire, array_oid, Format::Binary).unwrap();
        let text =
            PgArray::<String>::from_sql(b"[-2:-2]={\"ab \"}", array_oid, Format::Text).unwrap();
        assert_eq!(binary, text);
        assert_eq!(binary.elements(), ["ab "]);
        assert_eq!(binary.dimensions(), [dimension(1, -2)]);
    }
}
