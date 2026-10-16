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

/// Formats nonnegative Unix nanoseconds as canonical RFC 7231 / RFC 9110 HTTP-date (IMF-fixdate).
///
/// Output format: `Sun, 06 Nov 1994 08:49:37 GMT`.
#[must_use]
pub fn format_unix_nanos_http_date(unix_nanos: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let whole_seconds = unix_nanos / NANOS_PER_SECOND;
    let unix_days = whole_seconds / SECONDS_PER_DAY;
    let seconds_of_day = whole_seconds % SECONDS_PER_DAY;

    let day_name = DAYS[(unix_days % 7) as usize];
    let (year, month, day) = civil_date_from_unix_days(unix_days);
    let month_name = MONTHS[(month - 1) as usize];
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    let mut rendered = String::with_capacity(29);
    write!(
        rendered,
        "{day_name}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} GMT"
    )
    .expect("writing to a String cannot fail");
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
#[path = "utc_inline_tests.rs"]
mod tests;
