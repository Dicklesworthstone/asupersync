    use super::format_unix_nanos_rfc3339;

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
