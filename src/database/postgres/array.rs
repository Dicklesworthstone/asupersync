//! Shape-preserving PostgreSQL arrays, alongside the existing `Vec<T>` codec.

use super::{Format, FromSql, IsNull, PgArrayElement, PgError, ToSql, oid, text_is_binary};

const MAX_DIMENSIONS: usize = 6;
const MAX_WIRE_BYTES: usize = i32::MAX as usize;

fn invalid(message: &str) -> PgError {
    PgError::Protocol(format!("invalid PostgreSQL array: {message}"))
}

/// One nonempty PostgreSQL array axis with its original SQL subscript range.
///
/// Empty arrays have no axes; use [`PgArray::empty`] for those. PostgreSQL
/// requires both the length and the exclusive upper bound to fit in `i32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PgArrayDimension {
    length: usize,
    lower_bound: i32,
}

impl PgArrayDimension {
    /// Validate a positive length and its SQL lower bound, which may be negative.
    pub fn new(length: usize, lower_bound: i32) -> Result<Self, PgError> {
        let wire_length =
            i32::try_from(length).map_err(|_| invalid("dimension length exceeds i32::MAX"))?;
        if wire_length == 0 {
            return Err(invalid("empty arrays must have zero dimensions"));
        }
        lower_bound
            .checked_add(wire_length)
            .ok_or_else(|| invalid("dimension upper bound overflows i32"))?;
        Ok(Self {
            length,
            lower_bound,
        })
    }

    /// Number of elements along this axis.
    #[must_use]
    pub const fn length(self) -> usize {
        self.length
    }

    /// First valid SQL subscript along this axis.
    #[must_use]
    pub const fn lower_bound(self) -> i32 {
        self.lower_bound
    }

    /// Last valid SQL subscript along this axis.
    #[must_use]
    pub fn upper_bound(self) -> i32 {
        // Construction proved that length is positive and lower + length fits.
        let length = i32::try_from(self.length).expect("validated PostgreSQL dimension length");
        self.lower_bound + length - 1
    }
}

/// A rectangular PostgreSQL array retaining every dimension and lower bound.
///
/// Elements are stored in row-major order: the last subscript changes fastest.
/// Unlike the one-dimensional [`Vec<T>`] codec, this type round-trips the full
/// shape. Up to six nonempty dimensions are supported. PostgreSQL represents
/// an empty array with zero dimensions; no nonempty shape is silently erased.
///
/// Parameters use the binary wire format through [`PgArrayElement`]. Results
/// of the built-in array types decode from either binary or PostgreSQL's text
/// array syntax through [`FromSql`], including quoted/escaped values, SQL NULL
/// elements, and explicit bounds. Use `Option<T>` for nullable elements.
///
/// ```
/// use asupersync::database::postgres::{PgArray, PgArrayDimension};
///
/// let matrix = PgArray::new(
///     vec![PgArrayDimension::new(2, 0)?, PgArrayDimension::new(2, -1)?],
///     vec![Some(10_i32), None, Some(30), Some(40)],
/// )?;
/// assert_eq!(matrix.get(&[1, -1]), Some(&Some(30)));
/// // Bind `&matrix` through query_params/execute_params, then decode with
/// // row.get_typed::<PgArray<Option<i32>>>("matrix").
/// # Ok::<(), asupersync::database::postgres::PgError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgArray<T> {
    dimensions: Vec<PgArrayDimension>,
    elements: Vec<T>,
}

impl<T> PgArray<T> {
    /// Construct an array after checking rank, size, and exact element count.
    ///
    /// An empty dimension vector is valid only with an empty element vector.
    pub fn new(dimensions: Vec<PgArrayDimension>, elements: Vec<T>) -> Result<Self, PgError> {
        if shape_count(&dimensions)? != elements.len() {
            return Err(invalid("dimension product does not match element count"));
        }
        Ok(Self {
            dimensions,
            elements,
        })
    }

    /// Construct the canonical zero-dimensional empty array.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            dimensions: Vec::new(),
            elements: Vec::new(),
        }
    }

    /// Construct a one-dimensional array with SQL subscripts starting at one.
    /// An empty vector becomes the canonical empty array.
    pub fn from_vec(elements: Vec<T>) -> Result<Self, PgError> {
        if elements.is_empty() {
            return Ok(Self::empty());
        }
        Self::new(vec![PgArrayDimension::new(elements.len(), 1)?], elements)
    }

    /// The axes, ordered from outermost to innermost.
    #[must_use]
    pub fn dimensions(&self) -> &[PgArrayDimension] {
        &self.dimensions
    }

    /// Number of dimensions, or zero for an empty array.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.dimensions.len()
    }

    /// All elements in row-major order.
    #[must_use]
    pub fn elements(&self) -> &[T] {
        &self.elements
    }

    /// Mutate values without changing the validated shape or element count.
    pub fn elements_mut(&mut self) -> &mut [T] {
        &mut self.elements
    }

    /// Total number of elements, including SQL NULL elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Whether this is the zero-dimensional empty array.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Look up an element using its SQL subscripts, including nondefault bounds.
    #[must_use]
    pub fn get(&self, subscripts: &[i32]) -> Option<&T> {
        self.elements.get(self.offset(subscripts)?)
    }

    /// Mutably look up an element using its SQL subscripts.
    pub fn get_mut(&mut self, subscripts: &[i32]) -> Option<&mut T> {
        let offset = self.offset(subscripts)?;
        self.elements.get_mut(offset)
    }

    /// Recover the dimensions and row-major elements without copying.
    #[must_use]
    pub fn into_parts(self) -> (Vec<PgArrayDimension>, Vec<T>) {
        (self.dimensions, self.elements)
    }

    fn offset(&self, subscripts: &[i32]) -> Option<usize> {
        if subscripts.len() != self.dimensions.len() {
            return None;
        }
        let mut offset = 0_usize;
        for (dimension, &subscript) in self.dimensions.iter().zip(subscripts) {
            let index =
                usize::try_from(i64::from(subscript) - i64::from(dimension.lower_bound)).ok()?;
            if index >= dimension.length {
                return None;
            }
            offset = offset.checked_mul(dimension.length)?.checked_add(index)?;
        }
        Some(offset)
    }
}

impl<T> Default for PgArray<T> {
    fn default() -> Self {
        Self::empty()
    }
}

fn shape_count(dimensions: &[PgArrayDimension]) -> Result<usize, PgError> {
    if dimensions.len() > MAX_DIMENSIONS {
        return Err(invalid("more than six dimensions"));
    }
    let mut count = usize::from(!dimensions.is_empty());
    for dimension in dimensions {
        count = count
            .checked_mul(dimension.length)
            .ok_or_else(|| invalid("dimension product overflows"))?;
    }
    let minimum_wire_bytes = count
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(12 + dimensions.len() * 8))
        .ok_or_else(|| invalid("array wire length overflows"))?;
    if minimum_wire_bytes > MAX_WIRE_BYTES {
        return Err(invalid("array wire length exceeds i32::MAX"));
    }
    Ok(count)
}

fn append_wire(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PgError> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|length| length > MAX_WIRE_BYTES)
    {
        return Err(invalid("array wire length exceeds i32::MAX"));
    }
    output
        .try_reserve(bytes.len())
        .map_err(|_| invalid("array allocation failed"))?;
    output.extend_from_slice(bytes);
    Ok(())
}

impl<T: PgArrayElement> ToSql for PgArray<T> {
    fn to_sql(&self, output: &mut Vec<u8>) -> Result<IsNull, PgError> {
        if T::ARRAY_OID == 0
            || T::ELEMENT_OID == 0
            || oid::array_element(T::ARRAY_OID).is_some_and(|oid| oid != T::ELEMENT_OID)
        {
            return Err(invalid("array and element type OIDs do not match"));
        }
        // Stage the parameter so a rejected element never changes caller bytes.
        let mut encoded = Vec::new();
        let rank = super::array_length(self.dimensions.len(), "rank")?;
        append_wire(&mut encoded, &rank.to_be_bytes())?;
        append_wire(&mut encoded, &0_i32.to_be_bytes())?;
        append_wire(&mut encoded, &T::ELEMENT_OID.to_be_bytes())?;
        for dimension in &self.dimensions {
            let length = super::array_length(dimension.length, "dimension length")?;
            append_wire(&mut encoded, &length.to_be_bytes())?;
            append_wire(&mut encoded, &dimension.lower_bound.to_be_bytes())?;
        }
        let mut element = Vec::new();
        let mut has_null = false;
        for value in &self.elements {
            element.clear();
            match value.to_sql(&mut element)? {
                IsNull::Yes => {
                    if !element.is_empty() {
                        return Err(invalid("NULL element wrote bytes"));
                    }
                    has_null = true;
                    append_wire(&mut encoded, &(-1_i32).to_be_bytes())?;
                }
                IsNull::No => {
                    if value.format() == Format::Text && !text_is_binary(T::ELEMENT_OID) {
                        return Err(invalid("array element encodes as text instead of binary"));
                    }
                    validate_element_length(T::ELEMENT_OID, element.len())?;
                    let length = i32::try_from(element.len())
                        .map_err(|_| invalid("element length exceeds i32::MAX"))?;
                    append_wire(&mut encoded, &length.to_be_bytes())?;
                    append_wire(&mut encoded, &element)?;
                }
            }
        }
        encoded[4..8].copy_from_slice(&i32::from(has_null).to_be_bytes());
        output
            .try_reserve(encoded.len())
            .map_err(|_| invalid("array allocation failed"))?;
        output.extend_from_slice(&encoded);
        Ok(IsNull::No)
    }

    fn type_oid(&self) -> u32 {
        T::ARRAY_OID
    }

    fn binds_system_time(&self) -> bool {
        self.elements.iter().any(ToSql::binds_system_time)
    }
}

impl<T: FromSql> FromSql for PgArray<T> {
    fn from_sql(data: &[u8], array_oid: u32, format: Format) -> Result<Self, PgError> {
        if data.len() > MAX_WIRE_BYTES {
            return Err(invalid("array wire length exceeds i32::MAX"));
        }
        let element_oid =
            oid::array_element(array_oid).ok_or_else(|| invalid("unknown array type OID"))?;
        if !T::accepts(element_oid) {
            return Err(invalid(
                "element decoder does not accept the array element type",
            ));
        }
        match format {
            Format::Binary => decode_binary(data, element_oid),
            Format::Text => decode_text(data, element_oid),
        }
    }

    fn accepts(array_oid: u32) -> bool {
        oid::array_element(array_oid).is_some_and(T::accepts)
    }
}

fn validate_element_length(element_oid: u32, length: usize) -> Result<(), PgError> {
    let expected = match element_oid {
        oid::BOOL | oid::CHAR => Some(1),
        oid::INT2 => Some(2),
        oid::INT4 | oid::OID | oid::FLOAT4 | oid::DATE => Some(4),
        oid::INT8 | oid::FLOAT8 | oid::TIMESTAMP | oid::TIMESTAMPTZ => Some(8),
        oid::UUID | oid::INTERVAL => Some(16),
        _ => None,
    };
    if expected.is_some_and(|expected| length != expected) {
        return Err(invalid("incorrect binary element length"));
    }
    Ok(())
}

fn read_i32(data: &[u8], at: &mut usize) -> Result<i32, PgError> {
    let end = at
        .checked_add(4)
        .ok_or_else(|| invalid("wire offset overflows"))?;
    let bytes: [u8; 4] = data
        .get(*at..end)
        .ok_or_else(|| invalid("truncated binary header or element length"))?
        .try_into()
        .map_err(|_| invalid("truncated binary integer"))?;
    *at = end;
    Ok(i32::from_be_bytes(bytes))
}

fn binary_element<'a>(data: &'a [u8], at: &mut usize) -> Result<Option<&'a [u8]>, PgError> {
    let length = read_i32(data, at)?;
    if length == -1 {
        return Ok(None);
    }
    let length = usize::try_from(length).map_err(|_| invalid("negative element length"))?;
    let end = at
        .checked_add(length)
        .ok_or_else(|| invalid("element length overflows"))?;
    let element = data
        .get(*at..end)
        .ok_or_else(|| invalid("truncated binary element"))?;
    *at = end;
    Ok(Some(element))
}

fn decode_binary<T: FromSql>(data: &[u8], element_oid: u32) -> Result<PgArray<T>, PgError> {
    let mut at = 0;
    let rank = usize::try_from(read_i32(data, &mut at)?)
        .map_err(|_| invalid("negative dimension count"))?;
    if rank > MAX_DIMENSIONS {
        return Err(invalid("more than six dimensions"));
    }
    let flags = read_i32(data, &mut at)?;
    if !matches!(flags, 0 | 1) {
        return Err(invalid("binary null flag must be zero or one"));
    }
    if read_i32(data, &mut at)?.cast_unsigned() != element_oid {
        return Err(invalid("binary element OID does not match the array type"));
    }
    let mut dimensions = Vec::with_capacity(rank);
    for _ in 0..rank {
        let length = usize::try_from(read_i32(data, &mut at)?)
            .map_err(|_| invalid("negative dimension length"))?;
        let lower_bound = read_i32(data, &mut at)?;
        dimensions.push(PgArrayDimension::new(length, lower_bound)?);
    }
    let count = shape_count(&dimensions)?;
    if count > (data.len() - at) / 4 {
        return Err(invalid("element count exceeds available wire data"));
    }
    // Validate the complete framing before allocating values or calling a
    // downstream decoder; a malicious dimension cannot drive an allocation.
    let body = at;
    for _ in 0..count {
        match binary_element(data, &mut at)? {
            Some(element) => validate_element_length(element_oid, element.len())?,
            None if flags == 0 => return Err(invalid("NULL element without the binary null flag")),
            None => {}
        }
    }
    if at != data.len() {
        return Err(invalid("trailing bytes after binary array"));
    }
    let mut elements = Vec::new();
    elements
        .try_reserve_exact(count)
        .map_err(|_| invalid("array allocation failed"))?;
    at = body;
    for _ in 0..count {
        elements.push(super::decode_array_element(
            binary_element(data, &mut at)?,
            element_oid,
            Format::Binary,
        )?);
    }
    Ok(PgArray {
        dimensions,
        elements,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TextShape {
    lengths: [usize; MAX_DIMENSIONS],
    rank: usize,
}

struct TextElement<'a> {
    raw: &'a [u8],
    escaped: bool,
    null: bool,
}

struct TextParser<'a> {
    data: &'a [u8],
    at: usize,
}

fn whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

impl<'a> TextParser<'a> {
    fn skip_space(&mut self) {
        while self.data.get(self.at).is_some_and(|&byte| whitespace(byte)) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), PgError> {
        if self.data.get(self.at) != Some(&byte) {
            return Err(invalid("malformed text array delimiter"));
        }
        self.at += 1;
        Ok(())
    }

    fn integer(&mut self) -> Result<i32, PgError> {
        self.skip_space();
        let start = self.at;
        if matches!(self.data.get(self.at), Some(b'+' | b'-')) {
            self.at += 1;
        }
        let digits = self.at;
        while self.data.get(self.at).is_some_and(u8::is_ascii_digit) {
            self.at += 1;
        }
        if digits == self.at {
            return Err(invalid("missing dimension bound"));
        }
        let value = std::str::from_utf8(&self.data[start..self.at])
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| invalid("dimension bound overflows i32"))?;
        self.skip_space();
        Ok(value)
    }

    fn parse<F>(&mut self, mut emit: F) -> Result<Vec<PgArrayDimension>, PgError>
    where
        F: FnMut(TextElement<'a>) -> Result<(), PgError>,
    {
        self.skip_space();
        let mut dimensions = Vec::new();
        while self.data.get(self.at) == Some(&b'[') {
            if dimensions.len() == MAX_DIMENSIONS {
                return Err(invalid("more than six dimensions"));
            }
            self.at += 1;
            let first = self.integer()?;
            let (lower, upper) = if self.data.get(self.at) == Some(&b':') {
                self.at += 1;
                (first, self.integer()?)
            } else {
                (1, first)
            };
            self.expect(b']')?;
            let length = usize::try_from(i64::from(upper) - i64::from(lower) + 1)
                .map_err(|_| invalid("upper bound precedes lower bound"))?;
            dimensions.push(PgArrayDimension::new(length, lower)?);
            self.skip_space();
        }
        if !dimensions.is_empty() {
            self.expect(b'=')?;
            self.skip_space();
        }
        let shape = self.level(0, &mut emit)?;
        self.skip_space();
        if self.at != self.data.len() {
            return Err(invalid("trailing text after array"));
        }
        if dimensions.is_empty() {
            if shape.lengths[0] != 0 {
                for &length in &shape.lengths[..shape.rank] {
                    dimensions.push(PgArrayDimension::new(length, 1)?);
                }
            }
        } else if dimensions.len() != shape.rank
            || dimensions
                .iter()
                .zip(shape.lengths)
                .any(|(dimension, length)| dimension.length != length)
        {
            return Err(invalid(
                "declared dimensions do not match the text array shape",
            ));
        }
        shape_count(&dimensions)?;
        Ok(dimensions)
    }

    fn level<F>(&mut self, depth: usize, emit: &mut F) -> Result<TextShape, PgError>
    where
        F: FnMut(TextElement<'a>) -> Result<(), PgError>,
    {
        if depth == MAX_DIMENSIONS {
            return Err(invalid("more than six dimensions"));
        }
        self.expect(b'{')?;
        self.skip_space();
        let mut shape = TextShape {
            lengths: [0; MAX_DIMENSIONS],
            rank: 1,
        };
        if self.data.get(self.at) == Some(&b'}') {
            self.at += 1;
            if depth != 0 {
                return Err(invalid(
                    "empty nested arrays do not have a rectangular shape",
                ));
            }
            return Ok(shape);
        }
        let nested = self.data.get(self.at) == Some(&b'{');
        let mut child_shape = None;
        loop {
            if nested {
                let child = self.level(depth + 1, emit)?;
                if child_shape.is_some_and(|expected| child != expected) {
                    return Err(invalid("ragged multidimensional array"));
                }
                child_shape = Some(child);
            } else {
                emit(self.element()?)?;
            }
            shape.lengths[0] = shape.lengths[0]
                .checked_add(1)
                .ok_or_else(|| invalid("dimension length overflows"))?;
            self.skip_space();
            match self.data.get(self.at) {
                Some(b'}') => {
                    self.at += 1;
                    break;
                }
                Some(b',') => {
                    self.at += 1;
                    self.skip_space();
                }
                _ => return Err(invalid("expected a comma or closing brace")),
            }
        }
        if let Some(child) = child_shape {
            shape.rank = child.rank + 1;
            shape.lengths[1..shape.rank].copy_from_slice(&child.lengths[..child.rank]);
        }
        Ok(shape)
    }

    fn element(&mut self) -> Result<TextElement<'a>, PgError> {
        self.skip_space();
        let quoted = self.data.get(self.at) == Some(&b'"');
        if quoted {
            self.at += 1;
        }
        let start = self.at;
        let mut end = start;
        let mut escaped = false;
        loop {
            match self.data.get(self.at).copied() {
                Some(b'\\') => {
                    escaped = true;
                    self.at += 1;
                    if self.data.get(self.at).is_none() {
                        return Err(invalid("dangling text element escape"));
                    }
                    self.at += 1;
                    end = self.at;
                }
                Some(b'"') if quoted => {
                    end = self.at;
                    self.at += 1;
                    break;
                }
                Some(b',' | b'}') if !quoted => break,
                Some(b'{' | b'"') if !quoted => {
                    return Err(invalid("unquoted brace or quote in element"));
                }
                Some(byte) => {
                    self.at += 1;
                    if quoted || !whitespace(byte) {
                        end = self.at;
                    }
                }
                None => return Err(invalid("unterminated text array element")),
            }
        }
        if !quoted && start == end {
            return Err(invalid("empty unquoted text element"));
        }
        let raw = &self.data[start..end];
        Ok(TextElement {
            raw,
            escaped,
            null: !quoted && !escaped && raw.eq_ignore_ascii_case(b"NULL"),
        })
    }
}

fn decode_text<T: FromSql>(data: &[u8], element_oid: u32) -> Result<PgArray<T>, PgError> {
    if data.contains(&0) {
        return Err(invalid("NUL byte in text array"));
    }
    // The first pass checks all braces, bounds and rectangularity without
    // allocating element storage or invoking a downstream FromSql decoder.
    let dimensions = TextParser { data, at: 0 }.parse(|_| Ok(()))?;
    let mut elements = Vec::new();
    elements
        .try_reserve_exact(shape_count(&dimensions)?)
        .map_err(|_| invalid("array allocation failed"))?;
    let mut scratch = Vec::new();
    TextParser { data, at: 0 }.parse(|element| {
        let bytes = if element.null {
            None
        } else if element.escaped {
            scratch.clear();
            scratch
                .try_reserve(element.raw.len())
                .map_err(|_| invalid("element allocation failed"))?;
            let mut at = 0;
            while at < element.raw.len() {
                if element.raw[at] == b'\\' {
                    at += 1;
                }
                scratch.push(element.raw[at]);
                at += 1;
            }
            Some(scratch.as_slice())
        } else {
            Some(element.raw)
        };
        elements.push(super::decode_array_element(
            bytes,
            element_oid,
            Format::Text,
        )?);
        Ok(())
    })?;
    Ok(PgArray {
        dimensions,
        elements,
    })
}
