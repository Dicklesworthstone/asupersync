//! Focused fuzz target for TLS ClientHello SNI parsing.
//!
//! This target builds complete ClientHello handshake messages and validates:
//! - nested length-prefix bounds on the extensions and SNI list
//! - non-ASCII hostnames are rejected
//! - malformed encodings fail cleanly without panicking

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CLIENT_HELLO_TYPE: u8 = 0x01;
const SERVER_NAME_EXT: u16 = 0x0000;

#[derive(Arbitrary, Debug, Clone)]
enum FuzzScenario {
    ValidAscii {
        primary: Vec<u8>,
        secondary: Option<Vec<u8>>,
    },
    NonAsciiHostname {
        raw: Vec<u8>,
    },
    TruncatedClientHello {
        primary: Vec<u8>,
        truncate_at: u16,
    },
    ExtensionsLengthMismatch {
        primary: Vec<u8>,
        delta: i8,
    },
    SniExtensionLengthMismatch {
        primary: Vec<u8>,
        delta: i8,
    },
    SniListLengthMismatch {
        primary: Vec<u8>,
        delta: i8,
    },
    InvalidNameType {
        primary: Vec<u8>,
        name_type: u8,
    },
}

struct BuiltClientHello {
    bytes: Vec<u8>,
    extensions_len_pos: usize,
    sni_ext_len_pos: usize,
    sni_list_len_pos: usize,
}

struct TlsReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TlsReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, &'static str> {
        let byte = *self.data.get(self.pos).ok_or("missing u8")?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_u16(&mut self) -> Result<u16, &'static str> {
        let bytes = self.read_slice(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u24(&mut self) -> Result<usize, &'static str> {
        let bytes = self.read_slice(3)?;
        Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        if self.pos + len > self.data.len() {
            return Err("truncated input");
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

fn sanitize_hostname(raw: &[u8]) -> Vec<u8> {
    fn sanitize_label(bytes: &[u8], fallback: u8) -> Vec<u8> {
        let mut label: Vec<u8> = bytes
            .iter()
            .take(16)
            .map(|byte| match *byte % 37 {
                0..=25 => b'a' + (*byte % 26),
                26..=35 => b'0' + (*byte % 10),
                _ => b'-',
            })
            .collect();
        if label.is_empty() {
            label.push(fallback);
        }
        if label[0] == b'-' {
            label[0] = fallback;
        }
        if label[label.len() - 1] == b'-' {
            let last = label.len() - 1;
            label[last] = b'z';
        }
        label
    }

    let split = raw.len().min(16);
    let left = sanitize_label(&raw[..split], b'a');
    let right = sanitize_label(&raw[split..], b'b');
    let mut hostname = left;
    hostname.push(b'.');
    hostname.extend_from_slice(&right);
    hostname
}

fn force_non_ascii_hostname(raw: &[u8]) -> Vec<u8> {
    let mut hostname = sanitize_hostname(raw);
    if hostname.is_empty() {
        hostname.push(0x80);
    } else {
        hostname[0] = 0x80;
    }
    hostname
}

fn apply_delta(value: u16, delta: i8) -> u16 {
    let delta = match delta % 7 {
        0 => 1,
        n => n as i16,
    };
    if delta.is_negative() {
        value.saturating_sub(delta.unsigned_abs())
    } else {
        value.saturating_add(delta as u16)
    }
}

fn build_client_hello(entries: &[(u8, Vec<u8>)]) -> BuiltClientHello {
    let mut bytes = Vec::new();
    bytes.push(CLIENT_HELLO_TYPE);
    bytes.extend_from_slice(&[0, 0, 0]);

    let body_start = bytes.len();
    bytes.extend_from_slice(&0x0303_u16.to_be_bytes());
    bytes.extend_from_slice(&[0x41; 32]);
    bytes.push(0);
    bytes.extend_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(&0x1301_u16.to_be_bytes());
    bytes.push(1);
    bytes.push(0);

    let extensions_len_pos = bytes.len();
    bytes.extend_from_slice(&[0, 0]);

    bytes.extend_from_slice(&SERVER_NAME_EXT.to_be_bytes());
    let sni_ext_len_pos = bytes.len();
    bytes.extend_from_slice(&[0, 0]);
    let sni_list_len_pos = bytes.len();
    bytes.extend_from_slice(&[0, 0]);

    for (name_type, hostname) in entries {
        bytes.push(*name_type);
        bytes.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        bytes.extend_from_slice(hostname);
    }

    let sni_list_len = bytes.len() - (sni_list_len_pos + 2);
    bytes[sni_list_len_pos..sni_list_len_pos + 2]
        .copy_from_slice(&(sni_list_len as u16).to_be_bytes());
    let sni_ext_len = bytes.len() - (sni_ext_len_pos + 2);
    bytes[sni_ext_len_pos..sni_ext_len_pos + 2]
        .copy_from_slice(&(sni_ext_len as u16).to_be_bytes());
    let extensions_len = bytes.len() - (extensions_len_pos + 2);
    bytes[extensions_len_pos..extensions_len_pos + 2]
        .copy_from_slice(&(extensions_len as u16).to_be_bytes());

    let body_len = bytes.len() - body_start;
    bytes[1] = ((body_len >> 16) & 0xff) as u8;
    bytes[2] = ((body_len >> 8) & 0xff) as u8;
    bytes[3] = (body_len & 0xff) as u8;

    BuiltClientHello {
        bytes,
        extensions_len_pos,
        sni_ext_len_pos,
        sni_list_len_pos,
    }
}

fn validate_ascii_hostname(hostname: &[u8]) -> Result<String, &'static str> {
    if hostname.is_empty() {
        return Err("empty hostname");
    }
    if !hostname.is_ascii() {
        return Err("non-ascii hostname");
    }
    if hostname
        .iter()
        .any(|byte| *byte == 0 || byte.is_ascii_control() || *byte == b' ')
    {
        return Err("invalid hostname bytes");
    }
    String::from_utf8(hostname.to_vec()).map_err(|_| "invalid hostname utf8")
}

fn parse_sni_extension(data: &[u8]) -> Result<Vec<String>, &'static str> {
    let mut reader = TlsReader::new(data);
    let list_len = reader.read_u16()? as usize;
    let list = reader.read_slice(list_len)?;
    if reader.remaining() != 0 {
        return Err("sni extension trailing bytes");
    }

    let mut list_reader = TlsReader::new(list);
    let mut names = Vec::new();
    while list_reader.remaining() > 0 {
        let name_type = list_reader.read_u8()?;
        if name_type != 0 {
            return Err("unsupported server name type");
        }
        let name_len = list_reader.read_u16()? as usize;
        let hostname = list_reader.read_slice(name_len)?;
        names.push(validate_ascii_hostname(hostname)?);
    }

    if names.is_empty() {
        return Err("empty sni list");
    }

    Ok(names)
}

fn parse_client_hello_sni(data: &[u8]) -> Result<Vec<String>, &'static str> {
    let mut reader = TlsReader::new(data);
    if reader.read_u8()? != CLIENT_HELLO_TYPE {
        return Err("not a ClientHello");
    }
    let body_len = reader.read_u24()?;
    let body = reader.read_slice(body_len)?;
    if reader.remaining() != 0 {
        return Err("handshake trailing bytes");
    }

    let mut body_reader = TlsReader::new(body);
    body_reader.read_u16()?;
    body_reader.read_slice(32)?;
    let session_id_len = body_reader.read_u8()? as usize;
    if session_id_len > 32 {
        return Err("session id too long");
    }
    body_reader.read_slice(session_id_len)?;

    let cipher_suites_len = body_reader.read_u16()? as usize;
    if cipher_suites_len == 0 || !cipher_suites_len.is_multiple_of(2) {
        return Err("invalid cipher suites length");
    }
    body_reader.read_slice(cipher_suites_len)?;

    let compression_methods_len = body_reader.read_u8()? as usize;
    if compression_methods_len == 0 {
        return Err("missing compression methods");
    }
    body_reader.read_slice(compression_methods_len)?;

    let extensions_len = body_reader.read_u16()? as usize;
    let extensions = body_reader.read_slice(extensions_len)?;
    if body_reader.remaining() != 0 {
        return Err("client hello trailing bytes");
    }

    let mut ext_reader = TlsReader::new(extensions);
    while ext_reader.remaining() > 0 {
        let ext_type = ext_reader.read_u16()?;
        let ext_len = ext_reader.read_u16()? as usize;
        let ext_data = ext_reader.read_slice(ext_len)?;
        if ext_type == SERVER_NAME_EXT {
            return parse_sni_extension(ext_data);
        }
    }

    Err("missing server_name extension")
}

fn fuzz_scenario(scenario: FuzzScenario) {
    let (bytes, expected_ok) = match scenario {
        FuzzScenario::ValidAscii { primary, secondary } => {
            let mut expected = vec![sanitize_hostname(&primary)];
            let mut entries = vec![(0, expected[0].clone())];
            if let Some(secondary) = secondary {
                let secondary = sanitize_hostname(&secondary);
                expected.push(secondary.clone());
                entries.push((0, secondary));
            }
            (build_client_hello(&entries).bytes, Some(expected))
        }
        FuzzScenario::NonAsciiHostname { raw } => {
            let hello = build_client_hello(&[(0, force_non_ascii_hostname(&raw))]);
            (hello.bytes, None)
        }
        FuzzScenario::TruncatedClientHello {
            primary,
            truncate_at,
        } => {
            let mut hello = build_client_hello(&[(0, sanitize_hostname(&primary))]).bytes;
            if hello.len() > 1 {
                let cut = usize::from(truncate_at) % hello.len();
                hello.truncate(cut);
            }
            (hello, None)
        }
        FuzzScenario::ExtensionsLengthMismatch { primary, delta } => {
            let mut hello = build_client_hello(&[(0, sanitize_hostname(&primary))]);
            let current = u16::from_be_bytes([
                hello.bytes[hello.extensions_len_pos],
                hello.bytes[hello.extensions_len_pos + 1],
            ]);
            let updated = apply_delta(current, delta);
            hello.bytes[hello.extensions_len_pos..hello.extensions_len_pos + 2]
                .copy_from_slice(&updated.to_be_bytes());
            (hello.bytes, None)
        }
        FuzzScenario::SniExtensionLengthMismatch { primary, delta } => {
            let mut hello = build_client_hello(&[(0, sanitize_hostname(&primary))]);
            let current = u16::from_be_bytes([
                hello.bytes[hello.sni_ext_len_pos],
                hello.bytes[hello.sni_ext_len_pos + 1],
            ]);
            let updated = apply_delta(current, delta);
            hello.bytes[hello.sni_ext_len_pos..hello.sni_ext_len_pos + 2]
                .copy_from_slice(&updated.to_be_bytes());
            (hello.bytes, None)
        }
        FuzzScenario::SniListLengthMismatch { primary, delta } => {
            let mut hello = build_client_hello(&[(0, sanitize_hostname(&primary))]);
            let current = u16::from_be_bytes([
                hello.bytes[hello.sni_list_len_pos],
                hello.bytes[hello.sni_list_len_pos + 1],
            ]);
            let updated = apply_delta(current, delta);
            hello.bytes[hello.sni_list_len_pos..hello.sni_list_len_pos + 2]
                .copy_from_slice(&updated.to_be_bytes());
            (hello.bytes, None)
        }
        FuzzScenario::InvalidNameType { primary, name_type } => {
            let name_type = if name_type == 0 { 1 } else { name_type };
            let hello = build_client_hello(&[(name_type, sanitize_hostname(&primary))]);
            (hello.bytes, None)
        }
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parse_client_hello_sni(&bytes)
    }));

    match (result, expected_ok) {
        (Ok(Ok(names)), Some(expected)) => {
            let expected: Vec<String> = expected
                .into_iter()
                .map(|name| {
                    String::from_utf8(name)
                        .expect("sanitized hostname should always be valid utf-8")
                })
                .collect();
            assert_eq!(names, expected);
            assert!(names.iter().all(|name| name.is_ascii()));
        }
        (Ok(Err(_)), None) => {}
        (Ok(Ok(_)), None) => panic!("malformed SNI ClientHello unexpectedly accepted"),
        (Ok(Err(err)), Some(_)) => panic!("valid SNI ClientHello rejected: {err}"),
        (Err(_), _) => panic!("SNI parser panicked"),
    }
}

fuzz_target!(|scenario: FuzzScenario| {
    fuzz_scenario(scenario);
});
