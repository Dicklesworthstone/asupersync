use std::fs;
use std::io::Write;
use std::path::Path;

fn encode_golden_frame(field_len: usize, big_endian: bool, length_adjustment: isize) -> Vec<u8> {
    let payload = b"Hello, Golden Frame!";
    let length_val = (payload.len() as isize - length_adjustment) as u64;

    let mut header = vec![0; field_len];
    if big_endian {
        let bytes = length_val.to_be_bytes();
        header.copy_from_slice(&bytes[8 - field_len..]);
    } else {
        let bytes = length_val.to_le_bytes();
        header.copy_from_slice(&bytes[..field_len]);
    }

    let mut frame = header;
    frame.extend_from_slice(payload);
    frame
}

fn main() {
    let cases = vec![
        ("u8", 1usize, true, 0isize),
        ("u8_adjusted", 1, true, -2),
        ("u16_be", 2, true, 0),
        ("u16_be_adjusted", 2, true, -2),
        ("u16_le", 2, false, 0),
        ("u16_le_adjusted", 2, false, -2),
        ("u32_be", 4, true, 0),
        ("u32_be_adjusted", 4, true, -2),
        ("u32_le", 4, false, 0),
        ("u32_le_adjusted", 4, false, -2),
    ];

    let dir = Path::new("tests/goldens/length_delim");
    fs::create_dir_all(dir).unwrap();

    for (name, field_len, big_endian, adjustment) in cases {
        let encoded = encode_golden_frame(field_len, big_endian, adjustment);
        let path = dir.join(format!("{}.bin", name));
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&encoded).unwrap();
    }
}
