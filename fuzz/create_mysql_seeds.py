#!/usr/bin/env python3
"""Create seed corpus for MySQL wire protocol fuzzer."""

import os
import struct

CORPUS_DIR = "corpus/fuzz_mysql_wire_protocol"

def create_corpus_dir():
    os.makedirs(CORPUS_DIR, exist_ok=True)

def write_seed(name: str, data: bytes):
    with open(f"{CORPUS_DIR}/{name}", "wb") as f:
        f.write(data)
    print(f"Created seed: {name} ({len(data)} bytes)")

def create_packet_header(length: int, sequence: int) -> bytes:
    """Create a 4-byte MySQL packet header."""
    # Length is 3 bytes little endian, sequence is 1 byte
    length_bytes = struct.pack("<I", length)[:3]  # Take first 3 bytes
    seq_byte = struct.pack("B", sequence)
    return length_bytes + seq_byte

def create_lenenc_int(value: int) -> bytes:
    """Create a length-encoded integer."""
    if value <= 250:
        return struct.pack("B", value)
    elif value <= 0xFFFF:
        return struct.pack("<BH", 252, value)
    elif value <= 0xFFFFFF:
        return struct.pack("<BI", 253, value)[:4]  # Take first 4 bytes
    else:
        return struct.pack("<BQ", 254, value)

def create_ok_packet(affected_rows=0, last_insert_id=0, status_flags=0, warning_count=0) -> bytes:
    """Create a MySQL OK packet."""
    packet = b"\x00"  # OK packet marker
    packet += create_lenenc_int(affected_rows)
    packet += create_lenenc_int(last_insert_id)
    packet += struct.pack("<HH", status_flags, warning_count)
    return packet

def create_eof_packet(warning_count=0, status_flags=0) -> bytes:
    """Create a MySQL EOF packet."""
    packet = b"\xFE"  # EOF packet marker
    packet += struct.pack("<HH", warning_count, status_flags)
    return packet

def main():
    create_corpus_dir()

    # Basic edge cases
    write_seed("empty", b"")
    write_seed("single_byte", b"\x00")
    write_seed("three_bytes", b"\x00\x01\x02")

    # Valid packet headers
    write_seed("header_zero_length", create_packet_header(0, 0))
    write_seed("header_small", create_packet_header(10, 1))
    write_seed("header_medium", create_packet_header(1024, 2))
    write_seed("header_large", create_packet_header(65535, 3))

    # Invalid packet headers
    write_seed("header_max_length", create_packet_header(16777215, 0))  # Max allowed
    write_seed("header_too_large", create_packet_header(16777216, 0))   # Over max
    write_seed("header_sequence_255", create_packet_header(100, 255))

    # OK packets
    write_seed("ok_minimal", create_ok_packet())
    write_seed("ok_with_values", create_ok_packet(
        affected_rows=5, last_insert_id=123, status_flags=0x0002, warning_count=0))
    write_seed("ok_large_affected", create_ok_packet(affected_rows=0xFFFFFFFF))
    write_seed("ok_large_insert_id", create_ok_packet(last_insert_id=0xFFFFFFFFFFFFFFFF))

    # EOF packets
    write_seed("eof_minimal", create_eof_packet())
    write_seed("eof_with_status", create_eof_packet(warning_count=2, status_flags=0x0008))

    # Length-encoded integers
    write_seed("lenenc_small", create_lenenc_int(42))
    write_seed("lenenc_250", create_lenenc_int(250))
    write_seed("lenenc_251", create_lenenc_int(251))
    write_seed("lenenc_2byte", create_lenenc_int(1000))
    write_seed("lenenc_3byte", create_lenenc_int(100000))
    write_seed("lenenc_8byte", create_lenenc_int(0x123456789ABCDEF0))

    # Combined packet: header + OK payload
    ok_payload = create_ok_packet(affected_rows=10, last_insert_id=200)
    header = create_packet_header(len(ok_payload), 1)
    write_seed("packet_header_ok", header + ok_payload)

    # Combined packet: header + EOF payload
    eof_payload = create_eof_packet(warning_count=1, status_flags=0x0001)
    header = create_packet_header(len(eof_payload), 2)
    write_seed("packet_header_eof", header + eof_payload)

    # Edge cases
    write_seed("wrong_ok_marker", b"\x01" + create_ok_packet()[1:])  # Wrong marker
    write_seed("wrong_eof_marker", b"\xFF" + create_eof_packet()[1:])  # Wrong marker
    write_seed("truncated_ok", create_ok_packet()[:3])  # Truncated
    write_seed("truncated_eof", create_eof_packet()[:2])  # Truncated

    # Invalid length encodings
    write_seed("invalid_lenenc_251", b"\xFB")  # Reserved NULL marker
    write_seed("invalid_lenenc_255", b"\xFF")  # Invalid marker

    print(f"Created {len(os.listdir(CORPUS_DIR))} seed files in {CORPUS_DIR}")

if __name__ == "__main__":
    main()