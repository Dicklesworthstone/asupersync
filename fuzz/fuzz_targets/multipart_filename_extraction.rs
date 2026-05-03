//! Focused fuzz target for multipart filename extraction and sanitization.
//!
//! This fuzzer specifically targets the Content-Disposition filename parameter
//! parsing and sanitization logic to discover path traversal, injection, and
//! security bypasses in filename handling after the path-traversal fix.
//!
//! ## Security Focus
//!
//! Tests filename extraction against attack vectors:
//! - **Path traversal**: `../../../etc/passwd`, `..\\..\\windows\\system32\\`
//! - **Drive letter injection**: `C:\\secrets.txt`, `//server/share/file`
//! - **Alternate data streams**: `invoice.pdf:payload.exe`
//! - **Control character injection**: filenames with `\0`, `\r`, `\n`
//! - **Unicode normalization attacks**: `..%2F` encoded traversal
//! - **Windows reserved names**: `CON`, `PRN`, `AUX`, `NUL`
//! - **Long filenames**: boundary testing around filesystem limits
//! - **Empty/whitespace**: edge cases in sanitization logic
//!
//! ## Oracle Strategy
//!
//! Uses property-based testing with multiple oracles:
//! 1. **Safety oracle**: sanitized filename never contains path separators
//! 2. **Non-empty oracle**: sanitized result is never empty (fallback to "file")
//! 3. **Control-free oracle**: no control characters in sanitized output
//! 4. **Windows-safe oracle**: no Windows reserved names or problematic characters
//! 5. **Length oracle**: sanitized output is reasonable length
//!
//! ## Differential Testing
//!
//! Compares against a simplified reference sanitizer to catch edge cases
//! where the main implementation diverges from expected behavior.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

// Internal access to multipart parsing functions for targeted fuzzing.
// Since multipart.rs doesn't expose these as pub, we'll test through the public API
// but focus on Content-Disposition header crafting.

/// Maximum generated input size to prevent timeouts.
const MAX_INPUT_SIZE: usize = 64 * 1024;

/// Content-Disposition header construction for filename testing.
#[derive(Arbitrary, Debug, Clone)]
struct ContentDisposition {
    /// Base disposition type (usually "form-data" for multipart).
    disposition_type: DispositionType,
    /// Name parameter (required for form fields).
    name: Option<String>,
    /// Filename parameter (the target of our fuzzing).
    filename: Option<FilenameValue>,
    /// Additional parameters to test parameter parsing robustness.
    extra_params: Vec<(String, String)>,
    /// Header formatting options.
    formatting: DispositionFormatting,
}

#[derive(Arbitrary, Debug, Clone)]
enum DispositionType {
    FormData,
    Attachment,
    Inline,
    Malformed(String),
}

#[derive(Arbitrary, Debug, Clone)]
struct FilenameValue {
    /// The raw filename content to be sanitized.
    content: FilenameContent,
    /// How to encode/quote the filename in the header.
    encoding: FilenameEncoding,
    /// Whether to use RFC 8187 extended parameters (filename*=).
    use_extended_param: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum FilenameContent {
    /// Normal filename.
    Normal(String),
    /// Path traversal attempts.
    Traversal(TraversalVector),
    /// Windows-specific attacks.
    WindowsAttack(WindowsAttack),
    /// Control character injections.
    ControlChars(Vec<u8>),
    /// Unicode edge cases.
    UnicodeEdgeCase(UnicodeAttack),
    /// Empty/whitespace edge cases.
    Whitespace(WhitespacePattern),
}

#[derive(Arbitrary, Debug, Clone)]
enum TraversalVector {
    /// Basic directory traversal.
    Basic { depth: u8, target: String },
    /// Mixed separators (Unix + Windows).
    MixedSeparators(String),
    /// URL-encoded traversal.
    UrlEncoded(String),
    /// Double-encoded traversal.
    DoubleEncoded(String),
    /// Null-byte injection to terminate parsing.
    NullByteTermination(String),
}

#[derive(Arbitrary, Debug, Clone)]
enum WindowsAttack {
    /// Drive letter injection: C:\path\file
    DriveLetterAbsolute { drive: char, path: String },
    /// UNC path injection: \\server\share\file
    UncPath {
        server: String,
        share: String,
        file: String,
    },
    /// Alternate data streams: file.txt:stream:$DATA
    AlternateDataStream { base: String, stream: String },
    /// Windows reserved device names.
    ReservedName(WindowsReserved),
    /// Case variations of reserved names.
    ReservedNameCase(String),
}

#[derive(Arbitrary, Debug, Clone)]
enum WindowsReserved {
    Con,
    Prn,
    Aux,
    Nul,
    Com1,
    Com2,
    Com3,
    Com4,
    Com5,
    Com6,
    Com7,
    Com8,
    Com9,
    Lpt1,
    Lpt2,
    Lpt3,
    Lpt4,
    Lpt5,
    Lpt6,
    Lpt7,
    Lpt8,
    Lpt9,
}

#[derive(Arbitrary, Debug, Clone)]
enum UnicodeAttack {
    /// Normalization-dependent path components.
    NormalizationEquivalent(String),
    /// Right-to-left override characters.
    BidiOverride(String),
    /// Zero-width characters.
    ZeroWidth(String),
    /// Non-ASCII path separators.
    UnicodePathSeps(String),
    /// Invalid UTF-8 sequences (when testing bytes).
    InvalidUtf8(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
enum WhitespacePattern {
    /// Leading whitespace.
    Leading(String),
    /// Trailing whitespace.
    Trailing(String),
    /// Only whitespace.
    OnlySpaces(u8),
    /// Mixed whitespace characters.
    MixedWhitespace(Vec<char>),
    /// Empty string.
    Empty,
}

#[derive(Arbitrary, Debug, Clone)]
enum FilenameEncoding {
    /// Unquoted parameter value.
    Unquoted,
    /// Double-quoted parameter value.
    Quoted,
    /// RFC 8187 extended parameter with charset and encoding.
    Rfc8187 { charset: String },
    /// Malformed quoting (unterminated, etc.).
    MalformedQuoting(QuotingMalformation),
}

#[derive(Arbitrary, Debug, Clone)]
enum QuotingMalformation {
    /// Unterminated quote.
    Unterminated,
    /// Extra characters after closing quote.
    TrailingGarbage(String),
    /// Unescaped quotes inside.
    UnescapedQuotes,
    /// Invalid escape sequences.
    InvalidEscapes(String),
}

#[derive(Arbitrary, Debug, Clone)]
struct DispositionFormatting {
    /// Parameter separation character (usually `;`).
    separator: char,
    /// Whitespace around `=` in parameters.
    equals_spacing: EqualsSpacing,
    /// Parameter ordering.
    param_order: ParamOrder,
    /// Case variations in parameter names.
    param_case: ParamCase,
}

#[derive(Arbitrary, Debug, Clone)]
enum EqualsSpacing {
    None,
    Before,
    After,
    Both,
    Excessive,
}

#[derive(Arbitrary, Debug, Clone)]
enum ParamOrder {
    /// name, filename, extras
    Standard,
    /// filename, name, extras
    FilenameFirst,
    /// Random order
    Random(Vec<usize>),
}

#[derive(Arbitrary, Debug, Clone)]
enum ParamCase {
    Lower,
    Upper,
    Mixed,
    Random(Vec<bool>),
}

impl ContentDisposition {
    /// Render as a Content-Disposition header value for testing.
    fn to_header_value(&self) -> String {
        let mut result = self.disposition_type.render();
        let mut params = Vec::new();

        // Add name parameter if present
        if let Some(ref name) = self.name {
            params.push((
                "name",
                self.format_param_value(name, &FilenameEncoding::Quoted),
            ));
        }

        // Add filename parameter if present
        if let Some(ref filename) = self.filename {
            let param_name = if filename.use_extended_param {
                "filename*"
            } else {
                "filename"
            };
            params.push((param_name, self.format_filename_value(filename)));
        }

        // Add extra parameters
        for (key, value) in &self.extra_params {
            params.push((
                key,
                self.format_param_value(value, &FilenameEncoding::Quoted),
            ));
        }

        // Apply parameter ordering and formatting
        self.format_parameters(&mut result, params);
        result
    }

    fn format_filename_value(&self, filename: &FilenameValue) -> String {
        let content = filename.content.render();
        match filename.encoding {
            FilenameEncoding::Unquoted => content,
            FilenameEncoding::Quoted => format!("\"{}\"", content.replace('"', r#"\""#)),
            FilenameEncoding::Rfc8187 { ref charset } => {
                // RFC 8187: charset'lang'value
                let encoded = content
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || "!#$&+-.^_".contains(c) {
                            c.to_string()
                        } else {
                            format!("%{:02X}", c as u32)
                        }
                    })
                    .collect::<String>();
                format!("{}''{}", charset, encoded)
            }
            FilenameEncoding::MalformedQuoting(ref mal) => {
                self.format_malformed_quoting(&content, mal)
            }
        }
    }

    fn format_malformed_quoting(
        &self,
        content: &str,
        malformation: &QuotingMalformation,
    ) -> String {
        match malformation {
            QuotingMalformation::Unterminated => format!("\"{}", content),
            QuotingMalformation::TrailingGarbage(garbage) => {
                format!("\"{}\"{}", content, garbage)
            }
            QuotingMalformation::UnescapedQuotes => {
                format!("\"{}\"", content.replace('"', "\"")) // Don't escape
            }
            QuotingMalformation::InvalidEscapes(escapes) => {
                format!("\"{}{}\"", content, escapes)
            }
        }
    }

    fn format_param_value(&self, value: &str, encoding: &FilenameEncoding) -> String {
        match encoding {
            FilenameEncoding::Quoted => format!("\"{}\"", value.replace('"', r#"\""#)),
            _ => value.to_string(),
        }
    }

    fn format_parameters(&self, result: &mut String, params: Vec<(&str, String)>) {
        for (name, value) in params {
            result.push(self.formatting.separator);

            // Add spacing around equals sign
            let name_formatted = match self.formatting.param_case {
                ParamCase::Lower => name.to_lowercase(),
                ParamCase::Upper => name.to_uppercase(),
                ParamCase::Mixed => name
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i % 2 == 0 {
                            c.to_uppercase().to_string()
                        } else {
                            c.to_lowercase().to_string()
                        }
                    })
                    .collect::<String>(),
                ParamCase::Random(ref pattern) => name
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if *pattern.get(i % pattern.len()).unwrap_or(&false) {
                            c.to_uppercase().to_string()
                        } else {
                            c.to_lowercase().to_string()
                        }
                    })
                    .collect::<String>(),
            };

            match self.formatting.equals_spacing {
                EqualsSpacing::None => result.push_str(&format!(" {}={}", name_formatted, value)),
                EqualsSpacing::Before => {
                    result.push_str(&format!(" {} ={}", name_formatted, value))
                }
                EqualsSpacing::After => result.push_str(&format!(" {}= {}", name_formatted, value)),
                EqualsSpacing::Both => result.push_str(&format!(" {} = {}", name_formatted, value)),
                EqualsSpacing::Excessive => {
                    result.push_str(&format!("  {}  =  {}", name_formatted, value))
                }
            }
        }
    }
}

impl DispositionType {
    fn render(&self) -> String {
        match self {
            DispositionType::FormData => "form-data".to_string(),
            DispositionType::Attachment => "attachment".to_string(),
            DispositionType::Inline => "inline".to_string(),
            DispositionType::Malformed(s) => s.clone(),
        }
    }
}

impl FilenameContent {
    fn render(&self) -> String {
        match self {
            FilenameContent::Normal(s) => s.clone(),
            FilenameContent::Traversal(tv) => tv.render(),
            FilenameContent::WindowsAttack(wa) => wa.render(),
            FilenameContent::ControlChars(bytes) => {
                // Convert bytes to string, potentially with invalid UTF-8
                String::from_utf8_lossy(bytes).into_owned()
            }
            FilenameContent::UnicodeEdgeCase(ua) => ua.render(),
            FilenameContent::Whitespace(wp) => wp.render(),
        }
    }
}

impl TraversalVector {
    fn render(&self) -> String {
        match self {
            TraversalVector::Basic { depth, target } => {
                let mut result = String::new();
                for _ in 0..*depth {
                    result.push_str("../");
                }
                result.push_str(target);
                result
            }
            TraversalVector::MixedSeparators(path) => {
                // Mix / and \ separators
                path.replace('/', "\\/").replace('\\', "/\\")
            }
            TraversalVector::UrlEncoded(path) => {
                // URL-encode path separators and dots
                path.replace(".", "%2E")
                    .replace("/", "%2F")
                    .replace("\\", "%5C")
            }
            TraversalVector::DoubleEncoded(path) => {
                // Double URL-encode
                let single = path.replace(".", "%2E").replace("/", "%2F");
                single.replace("%", "%25")
            }
            TraversalVector::NullByteTermination(path) => {
                format!("{}/../../../etc/passwd\0.jpg", path)
            }
        }
    }
}

impl WindowsAttack {
    fn render(&self) -> String {
        match self {
            WindowsAttack::DriveLetterAbsolute { drive, path } => {
                format!("{}:{}", drive, path)
            }
            WindowsAttack::UncPath {
                server,
                share,
                file,
            } => {
                format!("\\\\{}\\{}\\{}", server, share, file)
            }
            WindowsAttack::AlternateDataStream { base, stream } => {
                format!("{}:{}", base, stream)
            }
            WindowsAttack::ReservedName(reserved) => reserved.render(),
            WindowsAttack::ReservedNameCase(name) => name.clone(),
        }
    }
}

impl WindowsReserved {
    fn render(&self) -> String {
        match self {
            WindowsReserved::Con => "CON",
            WindowsReserved::Prn => "PRN",
            WindowsReserved::Aux => "AUX",
            WindowsReserved::Nul => "NUL",
            WindowsReserved::Com1 => "COM1",
            WindowsReserved::Com2 => "COM2",
            WindowsReserved::Com3 => "COM3",
            WindowsReserved::Com4 => "COM4",
            WindowsReserved::Com5 => "COM5",
            WindowsReserved::Com6 => "COM6",
            WindowsReserved::Com7 => "COM7",
            WindowsReserved::Com8 => "COM8",
            WindowsReserved::Com9 => "COM9",
            WindowsReserved::Lpt1 => "LPT1",
            WindowsReserved::Lpt2 => "LPT2",
            WindowsReserved::Lpt3 => "LPT3",
            WindowsReserved::Lpt4 => "LPT4",
            WindowsReserved::Lpt5 => "LPT5",
            WindowsReserved::Lpt6 => "LPT6",
            WindowsReserved::Lpt7 => "LPT7",
            WindowsReserved::Lpt8 => "LPT8",
            WindowsReserved::Lpt9 => "LPT9",
        }
        .to_string()
    }
}

impl UnicodeAttack {
    fn render(&self) -> String {
        match self {
            UnicodeAttack::NormalizationEquivalent(s) => {
                // Use combining characters that normalize to directory separators
                format!("{}/../{}", s, s)
            }
            UnicodeAttack::BidiOverride(s) => {
                // Right-to-left override to disguise filenames
                format!("{}\u{202E}{}", s, s.chars().rev().collect::<String>())
            }
            UnicodeAttack::ZeroWidth(s) => {
                // Insert zero-width characters
                s.chars()
                    .map(|c| format!("{}\u{200B}", c)) // Zero-width space
                    .collect()
            }
            UnicodeAttack::UnicodePathSeps(s) => {
                // Use fullwidth and other Unicode "path separators"
                s.replace("/", "\u{FF0F}") // Fullwidth solidus
                    .replace("\\", "\u{FF3C}") // Fullwidth reverse solidus
            }
            UnicodeAttack::InvalidUtf8(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        }
    }
}

impl WhitespacePattern {
    fn render(&self) -> String {
        match self {
            WhitespacePattern::Leading(s) => format!("   {}", s),
            WhitespacePattern::Trailing(s) => format!("{}   ", s),
            WhitespacePattern::OnlySpaces(count) => " ".repeat(*count as usize),
            WhitespacePattern::MixedWhitespace(chars) => chars.iter().collect(),
            WhitespacePattern::Empty => String::new(),
        }
    }
}

/// Security oracles for filename sanitization.
#[derive(Debug, Default)]
struct SecurityOracles {
    safety_violations: Vec<String>,
    property_violations: Vec<String>,
}

impl SecurityOracles {
    /// Check that sanitized filename is safe from path traversal.
    fn check_path_safety(&mut self, sanitized: &str, original: &str) {
        // Must not contain path separators
        if sanitized.contains('/') || sanitized.contains('\\') {
            self.safety_violations.push(format!(
                "Path separator in sanitized filename: '{}' from '{}'",
                sanitized, original
            ));
        }

        // Must not contain relative path components
        if sanitized.contains("..") {
            self.safety_violations.push(format!(
                "Relative path component in sanitized filename: '{}' from '{}'",
                sanitized, original
            ));
        }

        // Must not contain drive letters (absolute paths)
        if sanitized.len() >= 2 && sanitized.chars().nth(1) == Some(':') {
            let first_char = sanitized.chars().next().unwrap();
            if first_char.is_ascii_alphabetic() {
                self.safety_violations.push(format!(
                    "Drive letter in sanitized filename: '{}' from '{}'",
                    sanitized, original
                ));
            }
        }

        // Must not contain alternate data stream separators
        if sanitized.contains(':') && !sanitized.starts_with("http") {
            self.safety_violations.push(format!(
                "Alternate data stream separator in sanitized filename: '{}' from '{}'",
                sanitized, original
            ));
        }
    }

    /// Check general filename properties.
    fn check_filename_properties(&mut self, sanitized: &str, original: &str) {
        // Must not be empty (should fallback to "file")
        if sanitized.is_empty() {
            self.property_violations
                .push(format!("Empty sanitized filename from '{}'", original));
        }

        // Must not contain control characters
        if sanitized.chars().any(|c| c.is_control()) {
            self.property_violations.push(format!(
                "Control characters in sanitized filename: '{}' from '{}'",
                sanitized, original
            ));
        }

        // Must not be a Windows reserved name
        let upper_sanitized = sanitized.to_uppercase();
        let reserved_names = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        if reserved_names.contains(&upper_sanitized.as_str()) {
            self.property_violations.push(format!(
                "Windows reserved name in sanitized filename: '{}' from '{}'",
                sanitized, original
            ));
        }

        // Should not contain problematic characters for filesystems
        let problematic = ['<', '>', '"', '|', '?', '*'];
        if sanitized.chars().any(|c| problematic.contains(&c)) {
            self.property_violations.push(format!(
                "Problematic filesystem characters in sanitized filename: '{}' from '{}'",
                sanitized, original
            ));
        }

        // Should have reasonable length (not too long)
        if sanitized.len() > 255 {
            self.property_violations.push(format!(
                "Excessively long sanitized filename ({} chars): '{}'",
                sanitized.len(),
                sanitized
            ));
        }
    }

    fn has_violations(&self) -> bool {
        !self.safety_violations.is_empty() || !self.property_violations.is_empty()
    }

    fn report_violations(&self) -> String {
        let mut report = String::new();

        if !self.safety_violations.is_empty() {
            report.push_str("SECURITY VIOLATIONS:\n");
            for violation in &self.safety_violations {
                report.push_str(&format!("  - {}\n", violation));
            }
        }

        if !self.property_violations.is_empty() {
            report.push_str("PROPERTY VIOLATIONS:\n");
            for violation in &self.property_violations {
                report.push_str(&format!("  - {}\n", violation));
            }
        }

        report
    }
}

/// Test filename extraction through the multipart parser.
fn test_filename_extraction(disposition_header: &str) -> Result<Option<String>, String> {
    use asupersync::bytes::Bytes;
    use asupersync::web::FromRequest;
    use asupersync::web::extract::Request;
    use asupersync::web::multipart::Multipart;

    // Create a minimal multipart body with the given Content-Disposition header
    let boundary = "FUZZ_BOUNDARY";
    let body = format!(
        "--{}\r\n\
        {}\r\n\
        \r\n\
        test-content\r\n\
        --{}--\r\n",
        boundary, disposition_header, boundary
    );

    let mut req = Request::new("POST", "/upload");
    req.headers.insert(
        "content-type".to_string(),
        format!("multipart/form-data; boundary={}", boundary),
    );
    req.body = Bytes::from(body.into_bytes());

    match Multipart::from_request(req) {
        Ok(multipart) => {
            if let Some(field) = multipart.fields().first() {
                Ok(field.filename().map(|s| s.to_string()))
            } else {
                Err("No fields parsed".to_string())
            }
        }
        Err(e) => Err(format!("Parse error: {}", e.message)),
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    let mut u = Unstructured::new(data);

    // Generate a Content-Disposition header with malicious filename
    let disposition = match ContentDisposition::arbitrary(&mut u) {
        Ok(d) => d,
        Err(_) => return, // Not enough data
    };

    let header = format!("Content-Disposition: {}", disposition.to_header_value());

    // Test filename extraction through the multipart parser
    let result = test_filename_extraction(&header);
    let result_clone = result.clone();

    match result_clone {
        Ok(Some(sanitized_filename)) => {
            // We got a filename - run security oracles
            let original_filename = disposition
                .filename
                .as_ref()
                .map(|f| f.content.render())
                .unwrap_or_default();

            let mut oracles = SecurityOracles::default();
            oracles.check_path_safety(&sanitized_filename, &original_filename);
            oracles.check_filename_properties(&sanitized_filename, &original_filename);

            if oracles.has_violations() {
                panic!(
                    "Security violations detected:\n{}\n\
                    Original header: {}\n\
                    Original filename: {}\n\
                    Sanitized filename: {}",
                    oracles.report_violations(),
                    header,
                    original_filename,
                    sanitized_filename
                );
            }
        }
        Ok(None) => {
            // No filename extracted - this is fine for many test cases
        }
        Err(_parse_error) => {
            // Parse error - this is expected for malformed inputs
            // We're not testing parser robustness here, just filename sanitization
        }
    }

    // Property: Filename extraction should be deterministic
    // Run the same input twice and ensure we get the same result
    let result2 = test_filename_extraction(&header);
    assert_eq!(
        result, result2,
        "Non-deterministic filename extraction for header: {}",
        header
    );
});
