    use super::{
        UtcCalendar, UtcClock, UtcError, UtcParseErrorKind, UtcTimestamp,
        format_unix_nanos_rfc3339,
    };
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn formats_fixed_nonnegative_unix_nanosecond_vectors() {
        let vectors = [
            (0, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:00.000000001Z"),
            (100_000_000, "1970-01-01T00:00:00.1Z"),
            (120_000_000, "1970-01-01T00:00:00.12Z"),
            (951_782_400_000_000_000, "2000-02-29T00:00:00Z"),
            (1_582_979_696_123_456_789, "2020-02-29T12:34:56.123456789Z"),
            (4_107_542_400_000_000_000, "2100-03-01T00:00:00Z"),
            (u64::MAX, "2554-07-21T23:34:33.709551615Z"),
        ];

        for (unix_nanos, expected) in vectors {
            assert_eq!(format_unix_nanos_rfc3339(unix_nanos), expected);
        }
    }

    #[test]
    fn crosses_day_and_gregorian_leap_boundaries_exactly() {
        let vectors = [
            (951_782_399_999_999_999, "2000-02-28T23:59:59.999999999Z"),
            (951_782_400_000_000_000, "2000-02-29T00:00:00Z"),
            (4_107_542_399_999_999_999, "2100-02-28T23:59:59.999999999Z"),
            (4_107_542_400_000_000_000, "2100-03-01T00:00:00Z"),
        ];

        for (unix_nanos, expected) in vectors {
            assert_eq!(format_unix_nanos_rfc3339(unix_nanos), expected);
        }
    }

    #[test]
    fn formats_http_date_vectors() {
        use super::format_unix_nanos_http_date;

        let vectors = [
            (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
            (784_111_777_000_000_000, "Sun, 06 Nov 1994 08:49:37 GMT"),
            (951_782_400_000_000_000, "Tue, 29 Feb 2000 00:00:00 GMT"),
            (1_582_979_696_123_456_789, "Sat, 29 Feb 2020 12:34:56 GMT"),
        ];

        for (unix_nanos, expected) in vectors {
            assert_eq!(format_unix_nanos_http_date(unix_nanos), expected);
        }
    }

    #[test]
    fn normalizes_pre_epoch_nanoseconds_and_floors_milliseconds() {
        let vectors = [
            (-1, -1, 999_999_999, -1, "1969-12-31T23:59:59.999999999Z"),
            (-999_999_999, -1, 1, -1000, "1969-12-31T23:59:59.000000001Z"),
            (-1_000_000_000, -1, 0, -1000, "1969-12-31T23:59:59Z"),
            (
                -1_000_000_001, -2, 999_999_999, -1001,
                "1969-12-31T23:59:58.999999999Z",
            ),
            (
                -86_400_000_000_001, -86_401, 999_999_999, -86_400_001,
                "1969-12-30T23:59:59.999999999Z",
            ),
        ];
        for (nanos, seconds, subsecond, millis, rendered) in vectors {
            let instant = UtcTimestamp::from_unix_nanos(nanos).unwrap();
            assert_eq!(instant.unix_nanos(), nanos);
            assert_eq!(instant.unix_seconds(), seconds);
            assert_eq!(instant.subsec_nanos(), subsecond);
            assert_eq!(instant.unix_millis(), millis);
            assert_eq!(instant.to_string(), rendered);
            assert_eq!(UtcTimestamp::from_unix_parts(seconds, subsecond), Ok(instant));
        }
        for millis in [-62_167_219_200_000, -1001, -1, 0, 1, 253_402_300_799_999] {
            assert_eq!(
                UtcTimestamp::from_unix_millis(millis).unwrap().unix_millis(),
                millis,
            );
        }
    }

    #[test]
    fn checks_instant_boundaries_and_preserves_epoch_ordering() {
        assert_eq!(UtcTimestamp::MIN.to_string(), "0000-01-01T00:00:00Z");
        assert_eq!(
            UtcTimestamp::MAX.to_string(),
            "9999-12-31T23:59:59.999999999Z",
        );
        assert_eq!(
            UtcTimestamp::from_unix_nanos(UtcTimestamp::MIN.unix_nanos()),
            Ok(UtcTimestamp::MIN),
        );
        assert_eq!(
            UtcTimestamp::from_unix_nanos(UtcTimestamp::MAX.unix_nanos()),
            Ok(UtcTimestamp::MAX),
        );
        for nanos in [
            i128::MIN,
            UtcTimestamp::MIN.unix_nanos() - 1,
            UtcTimestamp::MAX.unix_nanos() + 1,
            i128::MAX,
        ] {
            assert_eq!(
                UtcTimestamp::from_unix_nanos(nanos),
                Err(UtcError::TimestampOutOfRange),
            );
        }
        for seconds in [
            i64::MIN,
            UtcTimestamp::MIN.unix_seconds() - 1,
            UtcTimestamp::MAX.unix_seconds() + 1,
            i64::MAX,
        ] {
            assert_eq!(
                UtcTimestamp::from_unix_seconds(seconds),
                Err(UtcError::TimestampOutOfRange),
            );
        }
        assert!(UtcTimestamp::from_unix_parts(0, 1_000_000_000).is_err());
        assert!(UtcTimestamp::from_unix_parts(0, u32::MAX).is_err());
        let before = UtcTimestamp::from_unix_nanos(-1).unwrap();
        let after = UtcTimestamp::from_unix_nanos(1).unwrap();
        assert!(UtcTimestamp::MIN < before);
        assert!(before < UtcTimestamp::UNIX_EPOCH);
        assert!(UtcTimestamp::UNIX_EPOCH < after);
        assert!(after < UtcTimestamp::MAX);
    }

    #[test]
    fn validates_calendar_components_and_gregorian_centuries() {
        let valid = UtcCalendar {
            year: 2000,
            month: 2,
            day: 29,
            hour: 12,
            minute: 34,
            second: 56,
            nanosecond: 789_000_001,
        };
        assert_eq!(UtcTimestamp::from_calendar(valid).unwrap().calendar(), valid);
        let invalid = [
            (UtcCalendar { year: -1, ..valid }, "year"),
            (UtcCalendar { year: 10000, ..valid }, "year"),
            (UtcCalendar { month: 0, ..valid }, "month"),
            (UtcCalendar { month: 13, ..valid }, "month"),
            (UtcCalendar { day: 0, ..valid }, "day"),
            (UtcCalendar { day: 30, ..valid }, "day"),
            (UtcCalendar { year: 1900, ..valid }, "day"),
            (UtcCalendar { year: 2100, ..valid }, "day"),
            (UtcCalendar { month: 4, day: 31, ..valid }, "day"),
            (UtcCalendar { hour: 24, ..valid }, "hour"),
            (UtcCalendar { minute: 60, ..valid }, "minute"),
            (UtcCalendar { second: 60, ..valid }, "second"),
            (
                UtcCalendar { nanosecond: 1_000_000_000, ..valid },
                "nanosecond",
            ),
        ];
        for (calendar, expected_component) in invalid {
            match UtcTimestamp::from_calendar(calendar) {
                Err(UtcError::ComponentOutOfRange { component, .. }) => {
                    assert_eq!(component, expected_component);
                }
                other => panic!(
                    "expected invalid {expected_component} for {calendar:?}, got {other:?}",
                ),
            }
        }
        for (year, month, day, seconds) in [
            (0, 1, 1, -62_167_219_200),
            (0, 2, 29, -62_162_121_600),
            (0, 3, 1, -62_162_035_200),
            (1, 1, 1, -62_135_596_800),
            (1900, 3, 1, -2_203_891_200),
            (2000, 3, 1, 951_868_800),
        ] {
            let calendar = UtcCalendar {
                year,
                month,
                day,
                hour: 0,
                minute: 0,
                second: 0,
                nanosecond: 0,
            };
            let instant = UtcTimestamp::from_calendar(calendar).unwrap();
            assert_eq!(instant.unix_seconds(), seconds);
            assert_eq!(instant.calendar(), calendar);
        }
    }

    #[test]
    fn calendar_matches_chrono_across_a_complete_gregorian_cycle() {
        // Include the negative March-era boundary (year zero) and an entire
        // 400-year cycle, then exercise later centuries and the upper endpoint.
        for year in (0..400).chain([1600, 1900, 1969, 1970, 2000, 2100, 2400, 9999]) {
            for month in 1_u8..=12 {
                for day in 1_u8..=31 {
                    let calendar = UtcCalendar {
                        year,
                        month,
                        day,
                        hour: 12,
                        minute: 34,
                        second: 56,
                        nanosecond: 987_654_321,
                    };
                    let Some(date) =
                        chrono::NaiveDate::from_ymd_opt(year, u32::from(month), u32::from(day))
                    else {
                        assert!(UtcTimestamp::from_calendar(calendar).is_err(), "{calendar:?}");
                        continue;
                    };
                    let reference = date
                        .and_hms_nano_opt(12, 34, 56, 987_654_321)
                        .unwrap()
                        .and_utc();
                    let instant = UtcTimestamp::from_calendar(calendar).unwrap();
                    assert_eq!(instant.unix_seconds(), reference.timestamp(), "{calendar:?}");
                    assert_eq!(instant.subsec_nanos(), reference.timestamp_subsec_nanos());
                    assert_eq!(instant.calendar(), calendar);
                    assert_eq!(
                        UtcTimestamp::from_unix_parts(
                            reference.timestamp(), reference.timestamp_subsec_nanos(),
                        )
                        .unwrap()
                        .calendar(),
                        calendar,
                    );
                }
            }
        }
    }

    #[test]
    fn checked_duration_arithmetic_crosses_epoch_without_saturating() {
        let one_nanosecond = Duration::from_nanos(1);
        let before = UtcTimestamp::from_unix_nanos(-1).unwrap();
        assert_eq!(
            before.checked_add(one_nanosecond),
            Some(UtcTimestamp::UNIX_EPOCH),
        );
        assert_eq!(
            UtcTimestamp::UNIX_EPOCH.checked_sub(one_nanosecond),
            Some(before),
        );
        assert_eq!(UtcTimestamp::MAX.checked_add(one_nanosecond), None);
        assert_eq!(UtcTimestamp::MIN.checked_sub(one_nanosecond), None);
        assert_eq!(UtcTimestamp::UNIX_EPOCH.checked_add(Duration::MAX), None);
        assert_eq!(UtcTimestamp::UNIX_EPOCH.checked_sub(Duration::MAX), None);
        assert_eq!(
            UtcTimestamp::MIN.checked_add(Duration::ZERO),
            Some(UtcTimestamp::MIN),
        );
        assert_eq!(
            UtcTimestamp::MAX.checked_sub(Duration::ZERO),
            Some(UtcTimestamp::MAX),
        );
        assert_eq!(
            UtcTimestamp::UNIX_EPOCH.duration_since(before),
            Ok(one_nanosecond),
        );
        assert_eq!(
            before.duration_since(UtcTimestamp::UNIX_EPOCH),
            Err(UtcError::NegativeDuration),
        );
        let complete_range = UtcTimestamp::MAX.duration_since(UtcTimestamp::MIN).unwrap();
        assert_eq!(
            UtcTimestamp::MIN.checked_add(complete_range),
            Some(UtcTimestamp::MAX),
        );
        assert_eq!(
            UtcTimestamp::MAX.checked_sub(complete_range),
            Some(UtcTimestamp::MIN),
        );
        assert_eq!(complete_range, Duration::new(315_569_519_999, 999_999_999));
    }

    #[test]
    fn system_time_conversions_are_exact_on_both_sides_of_epoch() {
        for nanos in [
            -86_400_000_000_001_i128, -1_000_000_001, -100, -1, 0, 1, 100,
            1_000_000_001, 86_400_000_000_001,
        ] {
            let instant = UtcTimestamp::from_unix_nanos(nanos).unwrap();
            let magnitude = nanos.unsigned_abs();
            let duration = Duration::new(
                (magnitude / 1_000_000_000) as u64,
                (magnitude % 1_000_000_000) as u32,
            );
            let expected = if nanos < 0 {
                UNIX_EPOCH.checked_sub(duration)
            } else {
                UNIX_EPOCH.checked_add(duration)
            };
            match expected {
                Some(time) => {
                    let represented = UtcTimestamp::from_system_time(time).unwrap();
                    assert_eq!(UtcTimestamp::try_from(time), Ok(represented));
                    if represented == instant {
                        assert_eq!(instant.to_system_time(), Ok(time));
                        assert_eq!(std::time::SystemTime::try_from(instant), Ok(time));
                    } else {
                        // A successful SystemTime arithmetic operation is not
                        // sufficient evidence of exact nanosecond conversion.
                        assert_eq!(instant.to_system_time(), Err(UtcError::SystemTimePrecisionLoss));
                        assert_eq!(
                            std::time::SystemTime::try_from(instant),
                            Err(UtcError::SystemTimePrecisionLoss),
                        );
                    }
                }
                None => assert_eq!(instant.to_system_time(), Err(UtcError::SystemTimeOutOfRange)),
            }
        }
        if let Some(outside) = UNIX_EPOCH.checked_add(Duration::from_secs(253_402_300_800)) {
            assert_eq!(
                UtcTimestamp::from_system_time(outside),
                Err(UtcError::TimestampOutOfRange),
            );
        }
        if let Some(outside) = UNIX_EPOCH.checked_sub(Duration::from_secs(62_167_219_201)) {
            assert_eq!(
                UtcTimestamp::from_system_time(outside),
                Err(UtcError::TimestampOutOfRange),
            );
        }
    }

    #[test]
    fn utc_clock_is_explicit_and_preserves_provider_errors() {
        let reads = std::cell::Cell::new(0);
        let clock = || {
            let nanos = reads.get();
            reads.set(nanos + 1);
            UtcTimestamp::from_unix_nanos(nanos)
        };
        assert_eq!(clock.now(), Ok(UtcTimestamp::UNIX_EPOCH));
        assert_eq!(clock.now().unwrap().unix_nanos(), 1);
        let failing = || Err(UtcError::SystemTimeOutOfRange);
        assert_eq!(failing.now(), Err(UtcError::SystemTimeOutOfRange));
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn legacy_formatters_match_independent_chrono_values() {
        let mut unix_nanos = 0_u64;
        for _ in 0..1024 {
            let seconds = (unix_nanos / 1_000_000_000) as i64;
            let fraction = (unix_nanos % 1_000_000_000) as u32;
            let reference =
                chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, fraction).unwrap();
            let mut expected = reference.format("%Y-%m-%dT%H:%M:%S").to_string();
            if fraction != 0 {
                let digits = format!("{fraction:09}");
                expected.push('.');
                expected.push_str(digits.trim_end_matches('0'));
            }
            expected.push('Z');
            assert_eq!(format_unix_nanos_rfc3339(unix_nanos), expected);
            assert_eq!(
                super::format_unix_nanos_http_date(unix_nanos),
                reference.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
            );
            unix_nanos = unix_nanos
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
        }
    }

    #[test]
    fn parses_rfc3339_examples_offsets_and_exact_fractions() {
        let vectors = [
            ("1985-04-12T23:20:50.52Z", "1985-04-12T23:20:50.52Z"),
            ("1996-12-19T16:39:57-08:00", "1996-12-20T00:39:57Z"),
            ("1937-01-01T12:00:27.87+00:20", "1937-01-01T11:40:27.87Z"),
            ("1969-12-31T18:59:59.999999999-05:00", "1969-12-31T23:59:59.999999999Z"),
            ("1970-01-01t00:00:00z", "1970-01-01T00:00:00Z"),
            ("1970-01-01T00:00:00+00:00", "1970-01-01T00:00:00Z"),
            ("1970-01-01T00:00:00-00:00", "1970-01-01T00:00:00Z"),
            ("2000-03-01T00:30:00+01:00", "2000-02-29T23:30:00Z"),
            ("2000-02-29T23:59:00-00:01", "2000-03-01T00:00:00Z"),
            ("2000-01-01T00:00:00+23:59", "1999-12-31T00:01:00Z"),
            ("2000-01-01T00:00:00-23:59", "2000-01-01T23:59:00Z"),
            ("2024-02-29T12:34:56.000000000Z", "2024-02-29T12:34:56Z"),
            ("2024-02-29T12:34:56.120000000+05:30", "2024-02-29T07:04:56.12Z"),
            ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"),
            ("9999-12-31T23:59:59.999999999Z", "9999-12-31T23:59:59.999999999Z"),
        ];
        for (input, expected) in vectors {
            let parsed = UtcTimestamp::parse_rfc3339(input).unwrap();
            assert_eq!(parsed.to_rfc3339(), expected, "{input}");
            assert_eq!(input.parse::<UtcTimestamp>(), Ok(parsed));
            let reference = chrono::DateTime::parse_from_rfc3339(input).unwrap();
            assert_eq!(parsed.unix_seconds(), reference.timestamp(), "{input}");
            assert_eq!(parsed.subsec_nanos(), reference.timestamp_subsec_nanos());
        }
        for (fraction, nanos) in [
            ("1", 100_000_000),
            ("12", 120_000_000),
            ("123", 123_000_000),
            ("1234", 123_400_000),
            ("12345", 123_450_000),
            ("123456", 123_456_000),
            ("1234567", 123_456_700),
            ("12345678", 123_456_780),
            ("123456789", 123_456_789),
        ] {
            let input = format!("1970-01-01T00:00:00.{fraction}Z");
            let timestamp = UtcTimestamp::parse_rfc3339(&input).unwrap();
            assert_eq!(timestamp.unix_nanos(), nanos);
            assert_eq!(timestamp.to_rfc3339(), input);
        }
    }

    #[test]
    fn numeric_offsets_respect_the_normalized_utc_range() {
        let first = UtcTimestamp::parse_rfc3339("0000-01-01T23:59:00+23:59").unwrap();
        assert_eq!(first, UtcTimestamp::MIN);
        let last = UtcTimestamp::parse_rfc3339("9999-12-31T00:00:59.999999999-23:59").unwrap();
        assert_eq!(last, UtcTimestamp::MAX);
        for (input, offset) in [
            ("0000-01-01T00:00:00+00:01", 19),
            ("0000-01-01T23:58:59.999999999+23:59", 29),
            ("9999-12-31T23:59:59.999999999-00:01", 29),
            ("9999-12-31T00:01:00-23:59", 19),
        ] {
            let error = UtcTimestamp::parse_rfc3339(input).unwrap_err();
            assert_eq!(error.kind(), UtcParseErrorKind::TimestampOutOfRange, "{input}");
            assert_eq!(error.byte_offset(), offset);
        }
    }

    #[test]
    fn malformed_rfc3339_has_typed_errors_and_byte_positions() {
        let vectors = [
            ("", 0, UtcParseErrorKind::UnexpectedEnd),
            ("1970-01-01T00:00:00", 19, UtcParseErrorKind::UnexpectedEnd),
            ("1970-01-01T00:00:00.", 20, UtcParseErrorKind::UnexpectedEnd),
            ("1970-01-01T00:00:00.Z", 20, UtcParseErrorKind::Expected("fractional digit")),
            ("1970/01-01T00:00:00Z", 4, UtcParseErrorKind::Expected("'-' after year")),
            ("1970-01-01 00:00:00Z", 10, UtcParseErrorKind::Expected("'T'")),
            ("1970-01-01T00:00:00+00", 22, UtcParseErrorKind::UnexpectedEnd),
            ("1970-01-01T00:00:00+0000", 22, UtcParseErrorKind::Expected("':' in UTC offset")),
            ("1970-01-01T00:00:00.1234567890Z", 29, UtcParseErrorKind::ExcessPrecision),
            ("1990-12-31T23:59:60Z", 17, UtcParseErrorKind::UnsupportedLeapSecond),
            ("1990-12-31T15:59:60-08:00", 17, UtcParseErrorKind::UnsupportedLeapSecond),
            ("1970-01-01T00:00:00Z ", 20, UtcParseErrorKind::TrailingInput),
            ("1970-01-01T00:00:00Z\0", 20, UtcParseErrorKind::TrailingInput),
            ("1970-01-01T00:00:00+00:00:00", 25, UtcParseErrorKind::TrailingInput),
            ("+1970-01-01T00:00:00Z", 0, UtcParseErrorKind::Expected("ASCII digit")),
            ("1970-01-0éT00:00:00Z", 9, UtcParseErrorKind::Expected("ASCII digit")),
            ("1970-01-01💥00:00:00Z", 10, UtcParseErrorKind::Expected("'T'")),
        ];
        for (input, offset, reason) in vectors {
            let error = UtcTimestamp::parse_rfc3339(input).unwrap_err();
            assert_eq!(error.kind(), reason, "{input:?}");
            assert_eq!(error.byte_offset(), offset, "{input:?}");
            assert!(error.to_string().contains(&format!("byte {offset}")));
        }
        for (input, offset, component) in [
            ("2024-00-01T00:00:00Z", 5, "month"),
            ("2024-13-01T00:00:00Z", 5, "month"),
            ("2024-01-00T00:00:00Z", 8, "day"),
            ("1900-02-29T00:00:00Z", 8, "day"),
            ("2023-02-29T00:00:00Z", 8, "day"),
            ("2024-04-31T00:00:00Z", 8, "day"),
            ("2024-01-01T24:00:00Z", 11, "hour"),
            ("2024-01-01T00:60:00Z", 14, "minute"),
            ("2024-01-01T00:00:61Z", 17, "second"),
            ("2024-01-01T00:00:00+24:00", 20, "offset hour"),
            ("2024-01-01T00:00:00-00:60", 23, "offset minute"),
        ] {
            let error = UtcTimestamp::parse_rfc3339(input).unwrap_err();
            assert_eq!(error.byte_offset(), offset, "{input}");
            assert!(matches!(
                error.kind(),
                UtcParseErrorKind::InvalidComponent(UtcError::ComponentOutOfRange {
                    component: found, ..
                }) if found == component
            ), "{input}: {error}");
            assert!(std::error::Error::source(&error).is_some());
        }
    }

    #[test]
    fn bounded_parser_rejects_truncation_mutations_and_overlong_input() {
        let complete = "2024-02-29T12:34:56.123456789+05:30";
        assert_eq!(complete.len(), UtcTimestamp::MAX_RFC3339_LEN);
        for end in 0..complete.len() {
            let prefix = &complete[..end];
            let error = UtcTimestamp::parse_rfc3339(prefix).unwrap_err();
            assert_eq!(error.kind(), UtcParseErrorKind::UnexpectedEnd, "{prefix:?}");
            assert_eq!(error.byte_offset(), end, "{prefix:?}");
        }
        for input in [format!("{complete}Z"), "9".repeat(65_536), "💥".repeat(16_384)] {
            let error = UtcTimestamp::parse_rfc3339(&input).unwrap_err();
            assert_eq!(error.kind(), UtcParseErrorKind::InputTooLong);
            assert_eq!(error.byte_offset(), 35);
        }
        let baseline = b"2024-02-29T12:34:56.123456789Z";
        for position in 0..baseline.len() {
            for replacement in 0_u8..=127 {
                let mut bytes = baseline.to_vec();
                bytes[position] = replacement;
                let input = String::from_utf8(bytes).unwrap();
                match UtcTimestamp::parse_rfc3339(&input) {
                    Ok(timestamp) => {
                        // Any accepted mutation must agree with an independent
                        // RFC 3339 implementation, not merely roundtrip itself.
                        let reference = chrono::DateTime::parse_from_rfc3339(&input)
                            .unwrap_or_else(|error| panic!("accepted {input:?}: {error}"));
                        assert_eq!(timestamp.unix_seconds(), reference.timestamp());
                        assert_eq!(timestamp.subsec_nanos(), reference.timestamp_subsec_nanos());
                    }
                    Err(error) => assert!(error.byte_offset() <= input.len(), "{input:?}"),
                }
            }
        }
    }

    #[test]
    fn parser_and_canonical_format_roundtrip_across_full_timestamp_range() {
        for original in [
            UtcTimestamp::MIN,
            UtcTimestamp::MIN.checked_add(Duration::from_nanos(1)).unwrap(),
            UtcTimestamp::from_unix_nanos(-1).unwrap(),
            UtcTimestamp::UNIX_EPOCH,
            UtcTimestamp::MAX.checked_sub(Duration::from_nanos(1)).unwrap(),
            UtcTimestamp::MAX,
        ] {
            assert_eq!(UtcTimestamp::parse_rfc3339(&original.to_rfc3339()), Ok(original));
        }
        let span = UtcTimestamp::MAX.unix_seconds() - UtcTimestamp::MIN.unix_seconds() + 1;
        let mut state = 0_u64;
        for _ in 0..2048 {
            state = state.wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let seconds = UtcTimestamp::MIN.unix_seconds() + (state % span as u64) as i64;
            let nanos = (state.rotate_left(29) % 1_000_000_000) as u32;
            let original = UtcTimestamp::from_unix_parts(seconds, nanos).unwrap();
            let text = original.to_rfc3339();
            let reference = chrono::DateTime::parse_from_rfc3339(&text).unwrap();
            assert_eq!(reference.timestamp(), seconds, "{text}");
            assert_eq!(reference.timestamp_subsec_nanos(), nanos, "{text}");
            assert_eq!(text.parse::<UtcTimestamp>(), Ok(original));
        }
    }

    #[test]
    fn serde_persisted_timestamps_preserve_instants_and_optional_absence() {
        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct StoredTimes {
            created_at: UtcTimestamp,
            #[serde(default)]
            expires_at: Option<UtcTimestamp>,
        }
        let stored: StoredTimes = serde_json::from_str(
            r#"{"created_at":"1969-12-31T18:59:59.999999999-05:00","expires_at":null}"#,
        ).unwrap();
        assert_eq!(stored.created_at.unix_nanos(), -1);
        assert_eq!(stored.expires_at, None);
        let canonical = serde_json::to_string(&stored).unwrap();
        assert_eq!(canonical, r#"{"created_at":"1969-12-31T23:59:59.999999999Z","expires_at":null}"#);
        assert_eq!(serde_json::from_str::<StoredTimes>(&canonical).unwrap(), stored);
        let absent: StoredTimes = serde_json::from_str(
            r#"{"created_at":"1970-01-01T00:00:00.120000000Z"}"#,
        ).unwrap();
        assert_eq!(absent.expires_at, None);
        assert_eq!(absent.created_at.unix_nanos(), 120_000_000);
        assert_eq!(serde_json::to_string(&absent.created_at).unwrap(), "\"1970-01-01T00:00:00.12Z\"");
        for timestamp in [UtcTimestamp::MIN, stored.created_at, UtcTimestamp::UNIX_EPOCH, UtcTimestamp::MAX] {
            let json = serde_json::to_string(&timestamp).unwrap();
            assert_eq!(serde_json::from_str::<UtcTimestamp>(&json).unwrap(), timestamp);
            let with_expiry = StoredTimes { created_at: timestamp, expires_at: Some(timestamp) };
            let json = serde_json::to_string(&with_expiry).unwrap();
            assert_eq!(serde_json::from_str::<StoredTimes>(&json).unwrap(), with_expiry);
        }
        assert_eq!(serde_json::from_str::<Option<UtcTimestamp>>("null").unwrap(), None);
        assert!(serde_json::from_str::<StoredTimes>(r#"{"expires_at":null}"#).is_err());
        for invalid in ["null", "0", "{}", "[]", "\"\"", "\"2023-02-29T00:00:00Z\""] {
            assert!(serde_json::from_str::<UtcTimestamp>(invalid).is_err(), "{invalid}");
        }
        let error = serde_json::from_str::<UtcTimestamp>("\"1970-01-01T00:00:00.1234567890Z\"")
            .unwrap_err();
        assert!(error.to_string().contains("byte 29"));
        assert!(error.to_string().contains("nine fractional digits"));
    }
