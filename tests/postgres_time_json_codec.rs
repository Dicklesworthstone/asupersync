//! `SystemTime` (`timestamptz`/`timestamp`) and `serde_json::Value`
//! (`json`/`jsonb`) through the public PostgreSQL `ToSql` / `FromSql` codecs,
//! without a server. `tests/postgres_real_server.rs` round-trips the same
//! values through a real server.
#![cfg(feature = "postgres")]

use asupersync::database::postgres::{Format, FromSql, IsNull, ToSql, oid};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn encode(value: &dyn ToSql) -> Vec<u8> {
    let mut buf = Vec::new();
    assert_eq!(value.to_sql(&mut buf).expect("encode"), IsNull::No);
    buf
}

fn at(unix_seconds: i64, micros: u64) -> SystemTime {
    let base = if unix_seconds >= 0 {
        UNIX_EPOCH + Duration::from_secs(unix_seconds.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_secs(unix_seconds.unsigned_abs())
    };
    base + Duration::from_micros(micros)
}

fn text(value: &str, type_oid: u32) -> Result<SystemTime, asupersync::database::PgError> {
    SystemTime::from_sql(value.as_bytes(), type_oid, Format::Text)
}

/// 2000-01-01 00:00:00 UTC, PostgreSQL's epoch.
const PG_EPOCH: i64 = 946_684_800;

#[test]
fn system_time_binds_as_binary_timestamptz_microseconds_since_2000() {
    let pg_epoch = at(PG_EPOCH, 0);
    assert_eq!(pg_epoch.type_oid(), oid::TIMESTAMPTZ);
    assert_eq!(pg_epoch.format(), Format::Binary);
    assert_eq!(encode(&pg_epoch), 0_i64.to_be_bytes());
    assert_eq!(
        encode(&at(PG_EPOCH, 1_500_000)),
        1_500_000_i64.to_be_bytes()
    );
    assert_eq!(encode(&UNIX_EPOCH), (-PG_EPOCH * 1_000_000).to_be_bytes());
    // A sub-microsecond remainder is truncated toward the past, on both sides
    // of the Unix epoch.
    assert_eq!(
        encode(&(UNIX_EPOCH + Duration::from_nanos(1_999))),
        (-PG_EPOCH * 1_000_000 + 1).to_be_bytes()
    );
    assert_eq!(
        encode(&(UNIX_EPOCH - Duration::from_nanos(1))),
        (-PG_EPOCH * 1_000_000 - 1).to_be_bytes()
    );

    // Binary round trip.
    let instant = at(1_791_441_950, 123_456);
    let decoded = SystemTime::from_sql(&encode(&instant), oid::TIMESTAMPTZ, Format::Binary)
        .expect("binary decode");
    assert_eq!(decoded, instant);
    // Infinity has no SystemTime.
    assert!(
        SystemTime::from_sql(&i64::MAX.to_be_bytes(), oid::TIMESTAMPTZ, Format::Binary).is_err()
    );
    assert!(SystemTime::from_sql(&[0; 4], oid::TIMESTAMPTZ, Format::Binary).is_err());
}

#[test]
fn timestamps_decode_from_iso_text_output_with_offsets_and_eras() {
    // 2026-10-08 06:45:50 UTC, printed in UTC, in Asia/Kolkata and in a
    // negative-offset zone.
    let instant = at(1_791_441_950, 0);
    assert_eq!(
        text("2026-10-08 06:45:50+00", oid::TIMESTAMPTZ).unwrap(),
        instant
    );
    assert_eq!(
        text("2026-10-08 12:15:50+05:30", oid::TIMESTAMPTZ).unwrap(),
        instant
    );
    assert_eq!(
        text("2026-10-08 03:45:50-03", oid::TIMESTAMPTZ).unwrap(),
        instant
    );
    assert_eq!(
        text("2026-10-08 12:15:50.5+05:30", oid::TIMESTAMPTZ).unwrap(),
        at(1_791_441_950, 500_000)
    );
    assert_eq!(
        text("2026-10-08 06:45:50.000123+00", oid::TIMESTAMPTZ).unwrap(),
        at(1_791_441_950, 123)
    );
    // Local mean time offsets carry seconds.
    assert_eq!(
        text("1900-01-01 00:19:32+00:19:32", oid::TIMESTAMPTZ).unwrap(),
        at(-2_208_988_800, 0)
    );
    // `timestamp` has no offset and is read as UTC.
    assert_eq!(
        text("2026-10-08 06:45:50", oid::TIMESTAMP).unwrap(),
        instant
    );
    // Five-digit years, and BC dates (1 BC is astronomical year 0).
    assert_eq!(
        text("10000-01-01 00:00:00+00", oid::TIMESTAMPTZ).unwrap(),
        at(253_402_300_800, 0)
    );
    assert_eq!(
        text("0001-01-01 05:53:28+05:53:28 BC", oid::TIMESTAMPTZ).unwrap(),
        at(-62_167_219_200, 0)
    );

    for refused in [
        "infinity",
        "-infinity",
        "10/08/2026 06:45:50 UTC",
        "Thu Oct 08 06:45:50 2026 UTC",
        "2026-10-08",
        "2026-13-08 06:45:50+00",
        "2026-10-08 06:45:50.1234567+00",
        "2026-10-08 06:45+00",
    ] {
        assert!(text(refused, oid::TIMESTAMPTZ).is_err(), "{refused}");
    }
    assert!(<SystemTime as FromSql>::accepts(oid::TIMESTAMPTZ));
    assert!(<SystemTime as FromSql>::accepts(oid::TIMESTAMP));
    assert!(!<SystemTime as FromSql>::accepts(oid::DATE));
}

#[test]
fn timestamp_arrays_bind_and_decode() {
    let instants = vec![at(PG_EPOCH, 0), at(PG_EPOCH, 1_500_000)];
    assert_eq!(instants.type_oid(), oid::TIMESTAMPTZ_ARRAY);
    let mut expected = Vec::new();
    for word in [1_i32, 0, oid::TIMESTAMPTZ.cast_signed(), 2, 1, 8] {
        expected.extend_from_slice(&word.to_be_bytes());
    }
    expected.extend_from_slice(&0_i64.to_be_bytes());
    expected.extend_from_slice(&8_i32.to_be_bytes());
    expected.extend_from_slice(&1_500_000_i64.to_be_bytes());
    assert_eq!(encode(&instants), expected);

    let decoded = Vec::<SystemTime>::from_sql(
        br#"{"2000-01-01 00:00:00+00","2000-01-01 00:00:01.5+00"}"#,
        oid::TIMESTAMPTZ_ARRAY,
        Format::Text,
    )
    .expect("text array");
    assert_eq!(decoded, instants);
}

#[test]
fn json_values_bind_as_jsonb_text_and_decode_from_json_and_jsonb() {
    let value = serde_json::json!({"name": "a\"b", "tags": [1, 2.5, null], "ok": true});
    assert_eq!(value.type_oid(), oid::JSONB);
    assert_eq!(value.format(), Format::Text);
    let wire = encode(&value);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&wire).unwrap(),
        value
    );

    for type_oid in [oid::JSON, oid::JSONB] {
        let decoded = serde_json::Value::from_sql(&wire, type_oid, Format::Text).expect("text");
        assert_eq!(decoded, value);
    }
    let mut jsonb = vec![1_u8];
    jsonb.extend_from_slice(&wire);
    assert_eq!(
        serde_json::Value::from_sql(&jsonb, oid::JSONB, Format::Binary).expect("binary jsonb"),
        value
    );
    // `json` in binary is its text.
    assert_eq!(
        serde_json::Value::from_sql(&wire, oid::JSON, Format::Binary).expect("binary json"),
        value
    );
    let mut future = vec![2_u8];
    future.extend_from_slice(&wire);
    assert!(serde_json::Value::from_sql(&future, oid::JSONB, Format::Binary).is_err());
    assert!(serde_json::Value::from_sql(b"{not json", oid::JSONB, Format::Text).is_err());
    assert!(<serde_json::Value as FromSql>::accepts(oid::JSON));
    assert!(!<serde_json::Value as FromSql>::accepts(oid::TEXT));
}
