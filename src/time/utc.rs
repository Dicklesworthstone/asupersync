//! Deterministic UTC rendering for persisted Unix timestamps.
//!
//! This module owns calendar rendering only. It does not read a clock, parse
//! timestamps, apply time zones, or participate in runtime scheduling.

use std::fmt::Write as _;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const SECONDS_PER_DAY: u64 = 86_400;

/// Formats nonnegative Unix nanoseconds as canonical RFC 3339 UTC text.
///
/// The result uses an uppercase `Z`. A zero fractional component is omitted;
/// otherwise trailing fractional zeroes are removed while preserving the exact
/// nanosecond value. Every `u64` input is representable in the supported
/// `1970..=2554` year range.
///
/// This function treats `0` as the Unix epoch. Callers that use zero as an
/// absence sentinel must handle that policy before calling the formatter.
///
/// # Examples
///
/// ```
/// use asupersync::time::format_unix_nanos_rfc3339;
///
/// assert_eq!(
///     format_unix_nanos_rfc3339(1_577_836_800_000_000_000),
///     "2020-01-01T00:00:00Z"
/// );
/// assert_eq!(
///     format_unix_nanos_rfc3339(1_577_836_800_120_000_000),
///     "2020-01-01T00:00:00.12Z"
/// );
/// ```
#[must_use]
pub fn format_unix_nanos_rfc3339(unix_nanos: u64) -> String {
    let whole_seconds = unix_nanos / NANOS_PER_SECOND;
    let subsecond_nanos = unix_nanos % NANOS_PER_SECOND;
    let unix_days = whole_seconds / SECONDS_PER_DAY;
    let seconds_of_day = whole_seconds % SECONDS_PER_DAY;

    let (year, month, day) = civil_date_from_unix_days(unix_days);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;

    let mut rendered = String::with_capacity(30);
    write!(
        rendered,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"
    )
    .expect("writing to a String cannot fail");

    if subsecond_nanos != 0 {
        rendered.push('.');
        write!(rendered, "{subsecond_nanos:09}").expect("writing to a String cannot fail");
        while rendered.ends_with('0') {
            rendered.pop();
        }
    }
    rendered.push('Z');
    rendered
}

/// Converts days since 1970-01-01 to a proleptic Gregorian date.
///
/// This is the civil-from-days decomposition for the nonnegative domain used
/// by [`format_unix_nanos_rfc3339`]. The `u64` nanosecond input bounds the day
/// count far below `i64::MAX`.
fn civil_date_from_unix_days(unix_days: u64) -> (i64, i64, i64) {
    let shifted_days =
        i64::try_from(unix_days).expect("the u64 nanosecond domain fits in i64 days") + 719_468;
    let era = shifted_days / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
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
}
