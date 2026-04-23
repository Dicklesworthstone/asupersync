import os

with open("src/http/h2/hpack.rs", "r") as f:
    content = f.read()

# Replace encode_huffman to no longer be used or to append to BytesMut directly
# We need to change encode_string.

old_encode_string = """
/// Encode a string (with optional Huffman encoding per RFC 7541 Section 5.2).
#[inline]
fn encode_string(dst: &mut BytesMut, value: &str, use_huffman: bool) {
    if use_huffman {
        let encoded = encode_huffman(value.as_bytes());
        // High bit (0x80) signals Huffman-encoded string.
        encode_integer(dst, encoded.len(), 7, 0x80);
        dst.extend_from_slice(&encoded);
    } else {
        let bytes = value.as_bytes();
        encode_integer(dst, bytes.len(), 7, 0);
        dst.extend_from_slice(bytes);
    }
}
"""

new_encode_string = """
/// Encode a string (with optional Huffman encoding per RFC 7541 Section 5.2).
#[inline]
fn encode_string(dst: &mut BytesMut, value: &str, use_huffman: bool) {
    let bytes = value.as_bytes();
    if use_huffman {
        let bit_len: u64 = bytes.iter().map(|&b| u64::from(HUFFMAN_TABLE[b as usize].1)).sum();
        let byte_len = ((bit_len + 7) / 8) as usize;
        
        // High bit (0x80) signals Huffman-encoded string.
        encode_integer(dst, byte_len, 7, 0x80);
        
        dst.reserve(byte_len);
        let mut accumulator: u64 = 0;
        let mut bits: u32 = 0;
        
        for &byte in bytes {
            let (code, code_bits) = HUFFMAN_TABLE[byte as usize];
            let code_bits_u32 = u32::from(code_bits);
            accumulator = (accumulator << code_bits_u32) | u64::from(code);
            bits += code_bits_u32;
            
            while bits >= 8 {
                bits -= 8;
                dst.put_u8((accumulator >> bits) as u8);
                accumulator &= BIT_MASKS[bits as usize];
            }
        }
        
        if bits > 0 {
            let shift = 8 - bits;
            let pad = (1 << shift) - 1;
            dst.put_u8(((accumulator << shift) | pad) as u8);
        }
    } else {
        encode_integer(dst, bytes.len(), 7, 0);
        dst.extend_from_slice(bytes);
    }
}
"""

content = content.replace(old_encode_string.strip(), new_encode_string.strip())

with open("src/http/h2/hpack.rs", "w") as f:
    f.write(content)

print("Replaced encode_string")
