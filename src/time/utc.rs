//! Checked UTC timestamps and deterministic Gregorian calendar rendering.
//!
//! [`UtcTimestamp`] represents nanosecond-precision instants in proleptic
//! Gregorian years `0000..=9999`. Year zero follows astronomical year numbering.
//! Leap seconds are not represented. This calendar clock is separate from
//! [`crate::types::Time`], which is used for runtime scheduling.
//!
//! No operation here reads an ambient clock. Code that needs the current UTC
//! time supplies a [`UtcClock`], or explicitly converts a caller-provided
//! [`SystemTime`]. Existing public `chrono` timestamp fields are unchanged.

use std::fmt::{self, Write as _};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NANOS_PER_SECOND: i128 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// An invalid UTC component, unsupported instant, or failed checked conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UtcError {
    /// A calendar or subsecond component is outside its inclusive valid range.
    ComponentOutOfRange {
        /// Component name, such as `"month"` or `"nanosecond"`.
        component: &'static str,
        /// Supplied value.
        value: i64,
        /// Smallest accepted value.
        minimum: i64,
        /// Largest accepted value for the other supplied components.
        maximum: i64,
    },
    /// The instant falls outside Gregorian years `0000..=9999`.
    TimestampOutOfRange,
    /// A nonnegative duration was requested with the instants reversed.
    NegativeDuration,
    /// The platform's [`SystemTime`] cannot represent this instant.
    SystemTimeOutOfRange,
    /// The platform's [`SystemTime`] would discard nanosecond precision.
    SystemTimePrecisionLoss,
}

impl fmt::Display for UtcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ComponentOutOfRange {
                component,
                value,
                minimum,
                maximum,
            } => write!(f, "UTC {component} {value} is outside {minimum}..={maximum}"),
            Self::TimestampOutOfRange => {
                f.write_str("UTC timestamp is outside years 0000..=9999")
            }
            Self::NegativeDuration => f.write_str("UTC duration would be negative"),
            Self::SystemTimeOutOfRange => {
                f.write_str("UTC timestamp is outside the platform SystemTime range")
            }
            Self::SystemTimePrecisionLoss => {
                f.write_str("the platform SystemTime cannot preserve this UTC timestamp's precision")
            }
        }
    }
}

impl std::error::Error for UtcError {}

/// UTC calendar components in the proleptic Gregorian calendar.
///
/// Fields may be assembled freely; [`UtcTimestamp::from_calendar`] validates
/// every component, including month-specific day counts and leap years.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UtcCalendar {
    /// Astronomical year, in `0..=9999` for a valid timestamp.
    pub year: i32,
    /// Month, in `1..=12`.
    pub month: u8,
    /// Day of the month, starting at one.
    pub day: u8,
    /// Hour, in `0..=23`.
    pub hour: u8,
    /// Minute, in `0..=59`.
    pub minute: u8,
    /// Second, in `0..=59`; leap seconds are unsupported.
    pub second: u8,
    /// Nanoseconds within the second, in `0..=999_999_999`.
    pub nanosecond: u32,
}

/// A checked, nanosecond-precision UTC instant in years `0000..=9999`.
///
/// The representation is normalized: seconds are rounded toward negative
/// infinity and the nanosecond component is always nonnegative. Thus one
/// nanosecond before the Unix epoch has seconds `-1` and nanoseconds
/// `999_999_999`. Ordering and hashing use the instant, not its rendered text.
///
/// This type does not represent leap seconds, local time zones, or the wider
/// signed-year range supported by some other calendar libraries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTimestamp {
    unix_seconds: i64,
    subsec_nanos: u32,
}

impl UtcTimestamp {
    /// The first instant in year zero: `0000-01-01T00:00:00Z`.
    pub const MIN: Self = Self {
        unix_seconds: -62_167_219_200,
        subsec_nanos: 0,
    };

    /// The last nanosecond in year 9999.
    pub const MAX: Self = Self {
        unix_seconds: 253_402_300_799,
        subsec_nanos: 999_999_999,
    };

    /// `1970-01-01T00:00:00Z`.
    pub const UNIX_EPOCH: Self = Self {
        unix_seconds: 0,
        subsec_nanos: 0,
    };

    /// Constructs an instant from normalized seconds and nanoseconds.
    ///
    /// The nanosecond component must be less than one billion. It is added to
    /// the supplied whole second even when the seconds are negative.
    pub fn from_unix_parts(unix_seconds: i64, subsec_nanos: u32) -> Result<Self, UtcError> {
        validate_component("nanosecond", i64::from(subsec_nanos), 0, 999_999_999)?;
        if !(Self::MIN.unix_seconds..=Self::MAX.unix_seconds).contains(&unix_seconds) {
            return Err(UtcError::TimestampOutOfRange);
        }
        Ok(Self {
            unix_seconds,
            subsec_nanos,
        })
    }

    /// Constructs an instant at a whole Unix second, checking the year range.
    pub fn from_unix_seconds(unix_seconds: i64) -> Result<Self, UtcError> {
        Self::from_unix_parts(unix_seconds, 0)
    }

    /// Constructs an instant from signed milliseconds since the Unix epoch.
    pub fn from_unix_millis(unix_millis: i64) -> Result<Self, UtcError> {
        Self::from_unix_nanos(i128::from(unix_millis) * 1_000_000)
    }

    /// Constructs an instant from signed nanoseconds since the Unix epoch.
    pub fn from_unix_nanos(unix_nanos: i128) -> Result<Self, UtcError> {
        if !(Self::MIN.unix_nanos()..=Self::MAX.unix_nanos()).contains(&unix_nanos) {
            return Err(UtcError::TimestampOutOfRange);
        }
        Ok(Self {
            unix_seconds: unix_nanos.div_euclid(NANOS_PER_SECOND) as i64,
            subsec_nanos: unix_nanos.rem_euclid(NANOS_PER_SECOND) as u32,
        })
    }

    /// Constructs an instant after validating every Gregorian component.
    pub fn from_calendar(calendar: UtcCalendar) -> Result<Self, UtcError> {
        validate_component("year", i64::from(calendar.year), 0, 9999)?;
        validate_component("month", i64::from(calendar.month), 1, 12)?;
        validate_component(
            "day",
            i64::from(calendar.day),
            1,
            i64::from(days_in_month(calendar.year, calendar.month)),
        )?;
        validate_component("hour", i64::from(calendar.hour), 0, 23)?;
        validate_component("minute", i64::from(calendar.minute), 0, 59)?;
        validate_component("second", i64::from(calendar.second), 0, 59)?;
        let days = unix_days_from_civil_date(calendar.year, calendar.month, calendar.day);
        let seconds = days * SECONDS_PER_DAY
            + i64::from(calendar.hour) * 3_600
            + i64::from(calendar.minute) * 60
            + i64::from(calendar.second);
        Self::from_unix_parts(seconds, calendar.nanosecond)
    }

    /// Returns the UTC Gregorian components of this instant.
    #[must_use]
    pub fn calendar(self) -> UtcCalendar {
        let unix_days = self.unix_seconds.div_euclid(SECONDS_PER_DAY);
        let seconds_of_day = self.unix_seconds.rem_euclid(SECONDS_PER_DAY);
        let (year, month, day) = civil_date_from_unix_days(unix_days);
        UtcCalendar {
            year: year as i32,
            month: month as u8,
            day: day as u8,
            hour: (seconds_of_day / 3_600) as u8,
            minute: (seconds_of_day % 3_600 / 60) as u8,
            second: (seconds_of_day % 60) as u8,
            nanosecond: self.subsec_nanos,
        }
    }

    /// Returns Unix seconds rounded toward negative infinity.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.unix_seconds
    }

    /// Returns the nonnegative nanosecond component within the whole second.
    #[must_use]
    pub const fn subsec_nanos(self) -> u32 {
        self.subsec_nanos
    }

    /// Returns Unix milliseconds rounded toward negative infinity.
    ///
    /// For example, one nanosecond before the epoch returns `-1`, not zero.
    #[must_use]
    pub const fn unix_millis(self) -> i64 {
        self.unix_seconds * 1_000 + (self.subsec_nanos / 1_000_000) as i64
    }

    /// Returns the exact signed nanosecond distance from the Unix epoch.
    #[must_use]
    pub const fn unix_nanos(self) -> i128 {
        self.unix_seconds as i128 * NANOS_PER_SECOND + self.subsec_nanos as i128
    }

    /// Converts a caller-provided wall-clock value, checking the year range.
    pub fn from_system_time(time: SystemTime) -> Result<Self, UtcError> {
        let nanos = match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => duration_nanos(duration),
            Err(before_epoch) => -duration_nanos(before_epoch.duration()),
        };
        Self::from_unix_nanos(nanos)
    }

    /// Converts to the platform's wall-clock representation without saturation.
    ///
    /// A platform may support less than this type's complete calendar range or
    /// nanosecond precision. Both range and precision loss are explicit errors.
    pub fn to_system_time(self) -> Result<SystemTime, UtcError> {
        let nanos = self.unix_nanos();
        let magnitude = nanos.unsigned_abs();
        let duration = Duration::new(
            (magnitude / NANOS_PER_SECOND as u128) as u64,
            (magnitude % NANOS_PER_SECOND as u128) as u32,
        );
        let candidate = if nanos < 0 {
            UNIX_EPOCH.checked_sub(duration)
        } else {
            UNIX_EPOCH.checked_add(duration)
        }
        .ok_or(UtcError::SystemTimeOutOfRange)?;
        // Some platforms, including Windows, store coarser clock ticks and
        // checked arithmetic can succeed while discarding sub-tick precision.
        if Self::from_system_time(candidate) != Ok(self) {
            return Err(UtcError::SystemTimePrecisionLoss);
        }
        Ok(candidate)
    }

    /// Adds a nonnegative duration, returning `None` outside the year range.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        // Even Duration::MAX occupies fewer than 96 signed nanosecond bits.
        Self::from_unix_nanos(self.unix_nanos() + duration_nanos(duration)).ok()
    }

    /// Subtracts a nonnegative duration, returning `None` outside the year range.
    #[must_use]
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        Self::from_unix_nanos(self.unix_nanos() - duration_nanos(duration)).ok()
    }

    /// Returns the exact nonnegative elapsed duration, or an error if reversed.
    pub fn duration_since(self, earlier: Self) -> Result<Duration, UtcError> {
        let nanos = self.unix_nanos() - earlier.unix_nanos();
        if nanos < 0 {
            return Err(UtcError::NegativeDuration);
        }
        Ok(Duration::new(
            (nanos / NANOS_PER_SECOND) as u64,
            (nanos % NANOS_PER_SECOND) as u32,
        ))
    }

    /// Formats canonical RFC 3339 UTC text, omitting trailing fractional zeroes.
    ///
    /// A zero fraction is omitted entirely; other fractions use one to nine
    /// digits. This preserves the existing Unix-nanosecond formatter's bytes.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        self.to_string()
    }
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let UtcCalendar {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
        } = self.calendar();
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"
        )?;
        if nanosecond != 0 {
            let mut fraction = nanosecond;
            let mut width = 9;
            while fraction % 10 == 0 {
                fraction /= 10;
                width -= 1;
            }
            write!(f, ".{fraction:0width$}")?;
        }
        f.write_str("Z")
    }
}

impl TryFrom<SystemTime> for UtcTimestamp {
    type Error = UtcError;

    fn try_from(time: SystemTime) -> Result<Self, Self::Error> {
        Self::from_system_time(time)
    }
}

impl TryFrom<UtcTimestamp> for SystemTime {
    type Error = UtcError;

    fn try_from(timestamp: UtcTimestamp) -> Result<Self, Self::Error> {
        timestamp.to_system_time()
    }
}

/// An explicitly supplied source of UTC instants.
///
/// This trait has no ambient/default clock implementation and is unrelated to
/// scheduler deadlines. A closure can supply a fixed or replayed timestamp:
///
/// ```
/// use asupersync::time::{UtcClock, UtcTimestamp};
///
/// let clock = || Ok(UtcTimestamp::UNIX_EPOCH);
/// assert_eq!(clock.now().unwrap(), UtcTimestamp::UNIX_EPOCH);
/// ```
pub trait UtcClock {
    /// Reads the explicitly provided clock, preserving any conversion error.
    fn now(&self) -> Result<UtcTimestamp, UtcError>;
}

impl<F> UtcClock for F
where
    F: Fn() -> Result<UtcTimestamp, UtcError>,
{
    fn now(&self) -> Result<UtcTimestamp, UtcError> {
        self()
    }
}

fn duration_nanos(duration: Duration) -> i128 {
    i128::from(duration.as_secs()) * NANOS_PER_SECOND + i128::from(duration.subsec_nanos())
}

fn validate_component(
    component: &'static str,
    value: i64,
    minimum: i64,
    maximum: i64,
) -> Result<(), UtcError> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(UtcError::ComponentOutOfRange {
            component,
            value,
            minimum,
            maximum,
        })
    }
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

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
    UtcTimestamp::from_unix_nanos(i128::from(unix_nanos))
        .expect("the u64 nanosecond domain is within UTC years 0000..=9999")
        .to_rfc3339()
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

    let timestamp = UtcTimestamp::from_unix_nanos(i128::from(unix_nanos))
        .expect("the u64 nanosecond domain is within UTC years 0000..=9999");
    let UtcCalendar {
        year,
        month,
        day,
        hour,
        minute,
        second,
        ..
    } = timestamp.calendar();
    let unix_days = timestamp.unix_seconds().div_euclid(SECONDS_PER_DAY);
    let day_name = DAYS[unix_days.rem_euclid(7) as usize];
    let month_name = MONTHS[(month - 1) as usize];

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
/// Euclidean division also handles January and February of year zero, whose
/// March-based era is negative. Inputs come only from validated timestamps.
fn civil_date_from_unix_days(unix_days: i64) -> (i64, i64, i64) {
    let shifted_days = unix_days + 719_468;
    let era = shifted_days.div_euclid(146_097);
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

/// Converts an already-validated Gregorian date to days since 1970-01-01.
fn unix_days_from_civil_date(year: i32, month: u8, day: u8) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
#[path = "utc_inline_tests.rs"]
mod tests;
