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
//!
//! RFC 3339 parsing accepts a bounded nanosecond-precision profile and normalizes
//! numeric offsets to UTC. Serde uses that same string profile; it never treats
//! a missing or null timestamp as the Unix epoch.

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

/// The reason a timestamp failed the supported RFC 3339 profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UtcParseErrorKind {
    /// Input exceeds [`UtcTimestamp::MAX_RFC3339_LEN`] bytes.
    InputTooLong,
    /// Input ends before a required byte or component.
    UnexpectedEnd,
    /// A byte does not match the indicated ASCII token.
    Expected(&'static str),
    /// A parsed calendar or numeric-offset component is invalid.
    InvalidComponent(UtcError),
    /// Leap-second notation (`:60`) is outside this type's supported profile.
    UnsupportedLeapSecond,
    /// A fraction has more than nine digits; precision is never truncated.
    ExcessPrecision,
    /// Applying the numeric offset leaves Gregorian years `0000..=9999`.
    TimestampOutOfRange,
    /// Bytes follow the complete timestamp.
    TrailingInput,
}

impl fmt::Display for UtcParseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong => f.write_str("timestamp exceeds the 35-byte input limit"),
            Self::UnexpectedEnd => f.write_str("unexpected end of timestamp"),
            Self::Expected(token) => write!(f, "expected {token}"),
            Self::InvalidComponent(error) => fmt::Display::fmt(error, f),
            Self::UnsupportedLeapSecond => f.write_str("leap seconds are unsupported"),
            Self::ExcessPrecision => f.write_str("more than nine fractional digits are unsupported"),
            Self::TimestampOutOfRange => {
                f.write_str("normalized UTC timestamp is outside years 0000..=9999")
            }
            Self::TrailingInput => f.write_str("unexpected trailing input"),
        }
    }
}

/// A bounded RFC 3339 parse failure, without retaining the untrusted input.
///
/// The byte offset identifies an unexpected byte, the start of an invalid
/// component, or the end of truncated input. For overlong input it identifies
/// the first byte beyond the supported limit. Offsets count UTF-8 bytes, not
/// characters; the accepted timestamp syntax itself is ASCII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcParseError {
    byte_offset: usize,
    kind: UtcParseErrorKind,
}

impl UtcParseError {
    const fn new(byte_offset: usize, kind: UtcParseErrorKind) -> Self {
        Self { byte_offset, kind }
    }

    /// Returns the zero-based byte offset associated with the failure.
    #[must_use]
    pub const fn byte_offset(self) -> usize {
        self.byte_offset
    }

    /// Returns the typed failure reason.
    #[must_use]
    pub const fn kind(self) -> UtcParseErrorKind {
        self.kind
    }
}

impl fmt::Display for UtcParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid RFC 3339 timestamp at byte {}: {}", self.byte_offset, self.kind)
    }
}

impl std::error::Error for UtcParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            UtcParseErrorKind::InvalidComponent(error) => Some(error),
            _ => None,
        }
    }
}

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
///
/// [`std::str::FromStr`] and serde accept the same bounded RFC 3339 profile as
/// [`Self::parse_rfc3339`]. Serialization uses [`Self::to_rfc3339`], including
/// its trimmed fractional precision. It does not promise byte-identical serde
/// output to other timestamp types, which may retain extra fractional zeroes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTimestamp {
    unix_seconds: i64,
    subsec_nanos: u32,
}

impl UtcTimestamp {
    /// Maximum accepted RFC 3339 input length in bytes: four-digit year,
    /// nine-digit fraction, and a numeric `+HH:MM` or `-HH:MM` offset.
    pub const MAX_RFC3339_LEN: usize = 35;

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

    /// Parses a strict, bounded RFC 3339 timestamp and normalizes it to UTC.
    ///
    /// The accepted profile uses four-digit years, `T` or `t`, and either `Z`,
    /// `z`, or a numeric offset with hours `00..=23` and minutes `00..=59`.
    /// Fractions contain one to nine digits. Leap seconds, excess fractional
    /// precision, spaces, missing offsets, and trailing input are rejected.
    /// Both the local calendar date and the normalized UTC instant must lie
    /// within years `0000..=9999`.
    ///
    /// Numeric offsets are subtracted from the local time. `-00:00` is accepted
    /// because it specifies a known UTC instant with an unknown local offset;
    /// this instant-only type does not retain that offset provenance. Output
    /// always uses uppercase `T` and `Z` and trims fractional zeroes.
    ///
    /// Parsing performs no allocation, inspects at most 35 bytes, and rejects
    /// overlong input before examining its contents.
    ///
    /// ```
    /// use asupersync::time::UtcTimestamp;
    ///
    /// let timestamp = UtcTimestamp::parse_rfc3339("1969-12-31T18:59:59.999999999-05:00")?;
    /// assert_eq!(timestamp.unix_nanos(), -1);
    /// assert_eq!(timestamp.to_rfc3339(), "1969-12-31T23:59:59.999999999Z");
    /// # Ok::<(), asupersync::time::UtcParseError>(())
    /// ```
    pub fn parse_rfc3339(input: &str) -> Result<Self, UtcParseError> {
        let bytes = input.as_bytes();
        if bytes.len() > Self::MAX_RFC3339_LEN {
            return Err(UtcParseError::new(
                Self::MAX_RFC3339_LEN,
                UtcParseErrorKind::InputTooLong,
            ));
        }

        let year = parse_decimal(bytes, 0, 4)? as i32;
        expect_rfc3339_byte(bytes, 4, b'-', "'-' after year")?;
        let month = parse_decimal(bytes, 5, 2)? as u8;
        expect_rfc3339_byte(bytes, 7, b'-', "'-' after month")?;
        let day = parse_decimal(bytes, 8, 2)? as u8;
        match bytes.get(10).copied() {
            Some(b'T' | b't') => {}
            Some(_) => return Err(UtcParseError::new(10, UtcParseErrorKind::Expected("'T'"))),
            None => return Err(UtcParseError::new(10, UtcParseErrorKind::UnexpectedEnd)),
        }
        let hour = parse_decimal(bytes, 11, 2)? as u8;
        expect_rfc3339_byte(bytes, 13, b':', "':' after hour")?;
        let minute = parse_decimal(bytes, 14, 2)? as u8;
        expect_rfc3339_byte(bytes, 16, b':', "':' after minute")?;
        let second = parse_decimal(bytes, 17, 2)? as u8;

        let mut cursor = 19;
        let mut nanosecond = 0;
        if bytes.get(cursor) == Some(&b'.') {
            cursor += 1;
            let mut digits = 0;
            while let Some(&digit) = bytes.get(cursor) {
                if !digit.is_ascii_digit() {
                    break;
                }
                if digits == 9 {
                    return Err(UtcParseError::new(cursor, UtcParseErrorKind::ExcessPrecision));
                }
                nanosecond = nanosecond * 10 + u32::from(digit - b'0');
                cursor += 1;
                digits += 1;
            }
            if digits == 0 {
                let kind = if cursor == bytes.len() {
                    UtcParseErrorKind::UnexpectedEnd
                } else {
                    UtcParseErrorKind::Expected("fractional digit")
                };
                return Err(UtcParseError::new(cursor, kind));
            }
            for _ in digits..9 {
                nanosecond *= 10;
            }
        }

        let offset_start = cursor;
        let offset_seconds = match bytes.get(cursor).copied() {
            Some(b'Z' | b'z') => {
                cursor += 1;
                0
            }
            Some(sign @ (b'+' | b'-')) => {
                let hours = parse_decimal(bytes, cursor + 1, 2)?;
                expect_rfc3339_byte(bytes, cursor + 3, b':', "':' in UTC offset")?;
                let minutes = parse_decimal(bytes, cursor + 4, 2)?;
                validate_component("offset hour", i64::from(hours), 0, 23).map_err(|error| {
                    UtcParseError::new(cursor + 1, UtcParseErrorKind::InvalidComponent(error))
                })?;
                validate_component("offset minute", i64::from(minutes), 0, 59).map_err(|error| {
                    UtcParseError::new(cursor + 4, UtcParseErrorKind::InvalidComponent(error))
                })?;
                cursor += 6;
                let magnitude = i64::from(hours * 3_600 + minutes * 60);
                if sign == b'-' { -magnitude } else { magnitude }
            }
            Some(_) => {
                return Err(UtcParseError::new(
                    cursor,
                    UtcParseErrorKind::Expected("'Z' or a numeric UTC offset"),
                ));
            }
            None => return Err(UtcParseError::new(cursor, UtcParseErrorKind::UnexpectedEnd)),
        };
        if cursor != bytes.len() {
            return Err(UtcParseError::new(cursor, UtcParseErrorKind::TrailingInput));
        }

        let local = Self::from_calendar(UtcCalendar {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
        })
        .map_err(calendar_parse_error)?;
        Self::from_unix_parts(local.unix_seconds - offset_seconds, nanosecond).map_err(|_| {
            UtcParseError::new(offset_start, UtcParseErrorKind::TimestampOutOfRange)
        })
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

impl std::str::FromStr for UtcTimestamp {
    type Err = UtcParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_rfc3339(input)
    }
}

impl serde::Serialize for UtcTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for UtcTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TimestampVisitor;

        impl serde::de::Visitor<'_> for TimestampVisitor {
            type Value = UtcTimestamp;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an RFC 3339 timestamp in years 0000..=9999 with nanosecond precision")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                UtcTimestamp::parse_rfc3339(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(TimestampVisitor)
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

fn parse_decimal(bytes: &[u8], start: usize, count: usize) -> Result<u32, UtcParseError> {
    let mut value = 0;
    for offset in start..start + count {
        match bytes.get(offset).copied() {
            Some(digit @ b'0'..=b'9') => value = value * 10 + u32::from(digit - b'0'),
            Some(_) => {
                return Err(UtcParseError::new(offset, UtcParseErrorKind::Expected("ASCII digit")));
            }
            None => return Err(UtcParseError::new(offset, UtcParseErrorKind::UnexpectedEnd)),
        }
    }
    Ok(value)
}

fn expect_rfc3339_byte(
    bytes: &[u8],
    offset: usize,
    expected: u8,
    description: &'static str,
) -> Result<(), UtcParseError> {
    match bytes.get(offset).copied() {
        Some(byte) if byte == expected => Ok(()),
        Some(_) => Err(UtcParseError::new(offset, UtcParseErrorKind::Expected(description))),
        None => Err(UtcParseError::new(offset, UtcParseErrorKind::UnexpectedEnd)),
    }
}

fn calendar_parse_error(error: UtcError) -> UtcParseError {
    let offset = match error {
        UtcError::ComponentOutOfRange { component, value, .. } => match component {
            "month" => 5,
            "day" => 8,
            "hour" => 11,
            "minute" => 14,
            "second" if value == 60 => {
                return UtcParseError::new(17, UtcParseErrorKind::UnsupportedLeapSecond);
            }
            "second" => 17,
            "nanosecond" => 20,
            _ => 0,
        },
        _ => 0,
    };
    UtcParseError::new(offset, UtcParseErrorKind::InvalidComponent(error))
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
