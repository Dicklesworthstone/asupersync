#!/usr/bin/env python3
"""Create seed corpus for typed symbol parser fuzzer."""

import os
import struct

CORPUS_DIR = "corpus/fuzz_typed_symbol_parser"
MAGIC = b"TSYM"
HEADER_LEN = 27

def create_corpus_dir():
    os.makedirs(CORPUS_DIR, exist_ok=True)

def write_seed(name: str, data: bytes):
    with open(f"{CORPUS_DIR}/{name}", "wb") as f:
        f.write(data)
    print(f"Created seed: {name} ({len(data)} bytes)")

def create_header(version=1, type_id=1, format_byte=1, schema_hash=0, payload_len=0):
    """Create a typed symbol header."""
    header = bytearray(HEADER_LEN)
    header[0:4] = MAGIC
    header[4:6] = struct.pack("<H", version)  # u16 little endian
    header[6:14] = struct.pack("<Q", type_id)  # u64 little endian
    header[14] = format_byte
    header[15:23] = struct.pack("<Q", schema_hash)  # u64 little endian
    header[23:27] = struct.pack("<I", payload_len)  # u32 little endian
    return bytes(header)

def main():
    create_corpus_dir()

    # Basic edge cases
    write_seed("empty", b"")
    write_seed("single_byte", b"\x00")
    write_seed("magic_only", MAGIC)
    write_seed("almost_header", b"\x00" * (HEADER_LEN - 1))

    # Wrong magic variations
    write_seed("wrong_magic_null", b"\x00" * HEADER_LEN)
    write_seed("wrong_magic_ascii", b"TEST" + b"\x00" * (HEADER_LEN - 4))
    write_seed("wrong_magic_similar", b"TSYN" + b"\x00" * (HEADER_LEN - 4))

    # Valid headers with different parameters
    write_seed("valid_minimal", create_header())
    write_seed("valid_messagepack", create_header(format_byte=1))
    write_seed("valid_bincode", create_header(format_byte=2))
    write_seed("valid_json", create_header(format_byte=3))
    write_seed("valid_custom", create_header(format_byte=255))

    # Invalid format bytes
    write_seed("invalid_format_zero", create_header(format_byte=0))
    write_seed("invalid_format_four", create_header(format_byte=4))
    write_seed("invalid_format_128", create_header(format_byte=128))

    # Edge case values
    write_seed("max_version", create_header(version=65535))
    write_seed("max_type_id", create_header(type_id=0xFFFFFFFFFFFFFFFF))
    write_seed("max_schema_hash", create_header(schema_hash=0xFFFFFFFFFFFFFFFF))
    write_seed("max_payload_len", create_header(payload_len=0xFFFFFFFF))

    # Headers with payload length but no payload
    write_seed("payload_len_mismatch", create_header(payload_len=100))

    # Large but valid header
    write_seed("valid_large_values",
               create_header(version=12345, type_id=0x123456789ABCDEF0,
                           schema_hash=0xDEADBEEFCAFEBABE, payload_len=1024))

    print(f"Created {len(os.listdir(CORPUS_DIR))} seed files in {CORPUS_DIR}")

if __name__ == "__main__":
    main()