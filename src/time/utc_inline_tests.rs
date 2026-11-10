    use super::{UtcCalendar, UtcClock, UtcError, UtcTimestamp, format_unix_nanos_rfc3339};
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
