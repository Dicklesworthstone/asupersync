//! Public String decoders for PostgreSQL's non-text binary scalar types.
//! Follow-up to br-asupersync-qml5yb: binary array elements must use the same
//! logical values as scalar decoding, including NULLs, infinities and BC dates.
#![cfg(feature = "postgres")]

use asupersync::database::postgres::{Format, FromSql, PgArray, PgError, oid};

fn binary(data: &[u8], type_oid: u32) -> String {
    String::from_sql(data, type_oid, Format::Binary).expect("binary String decode")
}

fn interval(micros: i64, days: i32, months: i32) -> Vec<u8> {
    let mut data = micros.to_be_bytes().to_vec();
    data.extend_from_slice(&days.to_be_bytes());
    data.extend_from_slice(&months.to_be_bytes());
    data
}

fn array(element_oid: u32, dimensions: &[(i32, i32)], elements: &[Option<&[u8]>]) -> Vec<u8> {
    let mut data = i32::try_from(dimensions.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    data.extend_from_slice(&i32::from(elements.iter().any(Option::is_none)).to_be_bytes());
    data.extend_from_slice(&element_oid.to_be_bytes());
    for &(length, lower) in dimensions {
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(&lower.to_be_bytes());
    }
    for element in elements {
        if let Some(element) = element {
            data.extend_from_slice(&i32::try_from(element.len()).unwrap().to_be_bytes());
            data.extend_from_slice(element);
        } else {
            data.extend_from_slice(&(-1_i32).to_be_bytes());
        }
    }
    data
}

#[test]
fn uuid_binary_is_canonical_even_when_every_byte_is_valid_utf8() {
    assert_eq!(
        binary(b"0123456789abcdef", oid::UUID),
        "30313233-3435-3637-3839-616263646566"
    );
    assert_eq!(
        binary(&[0; 16], oid::UUID),
        "00000000-0000-0000-0000-000000000000"
    );
    assert_eq!(
        binary(&[0xff; 16], oid::UUID),
        "ffffffff-ffff-ffff-ffff-ffffffffffff"
    );
}

#[test]
fn dates_and_timestamps_render_negative_fractions_and_bc_eras() {
    assert_eq!(binary(&0_i32.to_be_bytes(), oid::DATE), "2000-01-01");
    assert_eq!(binary(&(-1_i32).to_be_bytes(), oid::DATE), "1999-12-31");
    // Astronomical year zero is PostgreSQL's 1 BC, not "0000" or "-0001".
    const BC_DAYS: i32 = -730_485;
    assert_eq!(binary(&BC_DAYS.to_be_bytes(), oid::DATE), "0001-01-01 BC");
    assert_eq!(
        binary(&(BC_DAYS - 1).to_be_bytes(), oid::DATE),
        "0002-12-31 BC"
    );
    assert_eq!(
        binary(&(-1_i64).to_be_bytes(), oid::TIMESTAMP),
        "1999-12-31 23:59:59.999999"
    );
    assert_eq!(
        binary(&1_250_000_i64.to_be_bytes(), oid::TIMESTAMPTZ),
        "2000-01-01 00:00:01.25+00"
    );
    let bc_micros = i64::from(BC_DAYS) * 86_400_000_000 + 1_234_000;
    assert_eq!(
        binary(&bc_micros.to_be_bytes(), oid::TIMESTAMP),
        "0001-01-01 00:00:01.234 BC"
    );
    assert_eq!(
        binary(&bc_micros.to_be_bytes(), oid::TIMESTAMPTZ),
        "0001-01-01 00:00:01.234+00 BC"
    );
}

#[test]
fn temporal_infinity_sentinels_are_not_rendered_as_finite_dates() {
    for (days, micros, expected) in [
        (i32::MIN, i64::MIN, "-infinity"),
        (i32::MAX, i64::MAX, "infinity"),
    ] {
        assert_eq!(binary(&days.to_be_bytes(), oid::DATE), expected);
        for type_oid in [oid::TIMESTAMP, oid::TIMESTAMPTZ] {
            assert_eq!(binary(&micros.to_be_bytes(), type_oid), expected);
        }
        assert_eq!(
            binary(&interval(micros, days, days), oid::INTERVAL),
            expected
        );
    }
}

#[test]
fn intervals_preserve_independent_signs_and_large_hour_counts() {
    assert_eq!(binary(&interval(0, 0, 0), oid::INTERVAL), "00:00:00");
    assert_eq!(
        binary(&interval(-1_250_000, 2, -3), oid::INTERVAL),
        "-3 mons 2 days -00:00:01.25"
    );
    assert_eq!(
        binary(&interval(90_000_000_000, -1, 1), oid::INTERVAL),
        "1 mon -1 day 25:00:00"
    );
    // A single minimum field is finite; only the full triple is a sentinel.
    assert_eq!(
        binary(&interval(i64::MIN, 0, 0), oid::INTERVAL),
        "-2562047788:00:54.775808"
    );
}

#[test]
fn fixed_width_binary_string_types_refuse_short_and_trailing_payloads() {
    for (type_oid, width) in [
        (oid::UUID, 16),
        (oid::DATE, 4),
        (oid::TIMESTAMP, 8),
        (oid::TIMESTAMPTZ, 8),
        (oid::INTERVAL, 16),
    ] {
        assert!(<String as FromSql>::accepts(type_oid));
        for length in [0, width - 1, width + 1] {
            assert!(
                matches!(
                    String::from_sql(&vec![0; length], type_oid, Format::Binary),
                    Err(PgError::Protocol(_))
                ),
                "OID {type_oid}, length {length}"
            );
        }
    }
}

#[test]
fn nullable_uuid_arrays_decode_in_one_or_multiple_dimensions() {
    let elements = [Some(b"0123456789abcdef".as_slice()), None];
    let expected = [
        Some("30313233-3435-3637-3839-616263646566".to_string()),
        None,
    ];
    let flat = array(oid::UUID, &[(2, 1)], &elements);
    assert_eq!(
        Vec::<Option<String>>::from_sql(&flat, oid::UUID_ARRAY, Format::Binary).unwrap(),
        expected
    );
    let shaped = array(oid::UUID, &[(1, -2), (2, 0)], &elements);
    let decoded = PgArray::<Option<String>>::from_sql(&shaped, oid::UUID_ARRAY, Format::Binary)
        .expect("UUID matrix");
    assert_eq!(decoded.elements(), expected);
    assert_eq!(decoded.get(&[-2, 0]), Some(&expected[0]));
    assert_eq!(decoded.get(&[-2, 1]), Some(&None));
    assert_eq!(decoded.dimensions()[0].lower_bound(), -2);
    assert_eq!(decoded.dimensions()[1].lower_bound(), 0);
}

#[test]
fn temporal_arrays_use_binary_scalar_decoding_including_nulls() {
    for (type_oid, array_oid, payload, expected) in [
        (
            oid::DATE,
            oid::DATE_ARRAY,
            (-1_i32).to_be_bytes().to_vec(),
            "1999-12-31",
        ),
        (
            oid::TIMESTAMP,
            oid::TIMESTAMP_ARRAY,
            (-1_i64).to_be_bytes().to_vec(),
            "1999-12-31 23:59:59.999999",
        ),
        (
            oid::TIMESTAMPTZ,
            oid::TIMESTAMPTZ_ARRAY,
            0_i64.to_be_bytes().to_vec(),
            "2000-01-01 00:00:00+00",
        ),
        (
            oid::INTERVAL,
            oid::INTERVAL_ARRAY,
            interval(-1, 0, 0),
            "-00:00:00.000001",
        ),
    ] {
        let bytes = array(type_oid, &[(2, -1)], &[None, Some(&payload)]);
        let expected = [None, Some(expected.to_string())];
        assert_eq!(
            Vec::<Option<String>>::from_sql(&bytes, array_oid, Format::Binary).unwrap(),
            expected
        );
        assert_eq!(
            PgArray::<Option<String>>::from_sql(&bytes, array_oid, Format::Binary)
                .unwrap()
                .elements(),
            expected
        );
    }
}

#[test]
fn text_and_jsonb_string_decoding_keep_their_existing_representation() {
    for (type_oid, text) in [
        (oid::UUID, "ABCDEF01-2345-6789-ABCD-EF0123456789"),
        (oid::DATE, "01/02/2000"),
        (oid::TIMESTAMP, "0001-01-01 00:00:00 BC"),
        (oid::TIMESTAMPTZ, "2000-01-01 05:30:00+05:30"),
        (oid::INTERVAL, "P1Y2M3D"),
    ] {
        assert_eq!(
            String::from_sql(text.as_bytes(), type_oid, Format::Text).unwrap(),
            text
        );
    }
    for type_oid in [
        oid::TEXT,
        oid::VARCHAR,
        oid::BPCHAR,
        oid::NAME,
        oid::CHAR,
        oid::JSON,
    ] {
        assert_eq!(binary(b"plain", type_oid), "plain");
    }
    assert_eq!(binary(b"\x01{\"value\":1}", oid::JSONB), "{\"value\":1}");
    assert!(String::from_sql(b"\x02{}", oid::JSONB, Format::Binary).is_err());
}
