#!/usr/bin/env python3
"""Generate seed corpus for lines_codec_boundary_case fuzz target.

This script creates seed inputs that target specific boundary conditions
for the LineCodec max_length + LF/CRLF interaction.
"""

import os
import struct

def create_seed(name: str, data: bytes):
    """Create a seed file with the given name and data."""
    corpus_dir = "/data/projects/asupersync/fuzz/corpus/lines_codec_boundary_case"
    os.makedirs(corpus_dir, exist_ok=True)

    with open(f"{corpus_dir}/{name}", "wb") as f:
        f.write(data)
    print(f"Created seed: {name} ({len(data)} bytes)")

def main():
    """Generate boundary-focused seed inputs."""

    # Since our fuzz target uses Arbitrary, we need to create inputs that can be
    # deserialized into BoundaryFuzzInput. For simplicity, we'll create minimal
    # binary inputs that represent reasonable configurations.

    # Seed 1: Minimal input - small max_length, single segment at boundary
    # max_length=5, single segment with length_offset=0 (exactly at boundary), LF ending
    seed1 = struct.pack('<B', 5)  # max_length
    seed1 += struct.pack('<B', 1)  # segments.len() = 1
    seed1 += struct.pack('<b', 0)  # length_offset = 0 (exact boundary)
    seed1 += struct.pack('<B', 0)  # ending = Lf (0)
    seed1 += struct.pack('<B', ord('A'))  # fill_byte = 'A'
    seed1 += struct.pack('<B', 0)  # test_chunked = false
    create_seed("boundary_exact_lf", seed1)

    # Seed 2: Over boundary by 1 with LF
    seed2 = struct.pack('<B', 5)  # max_length
    seed2 += struct.pack('<B', 1)  # segments.len() = 1
    seed2 += struct.pack('<b', 1)  # length_offset = +1 (over boundary)
    seed2 += struct.pack('<B', 0)  # ending = Lf (0)
    seed2 += struct.pack('<B', ord('B'))  # fill_byte = 'B'
    seed2 += struct.pack('<B', 0)  # test_chunked = false
    create_seed("boundary_over_lf", seed2)

    # Seed 3: Over boundary by 1 with CRLF (should behave differently)
    seed3 = struct.pack('<B', 5)  # max_length
    seed3 += struct.pack('<B', 1)  # segments.len() = 1
    seed3 += struct.pack('<b', 1)  # length_offset = +1 (over boundary)
    seed3 += struct.pack('<B', 1)  # ending = Crlf (1)
    seed3 += struct.pack('<B', ord('C'))  # fill_byte = 'C'
    seed3 += struct.pack('<B', 0)  # test_chunked = false
    create_seed("boundary_over_crlf", seed3)

    # Seed 4: Mixed LF and CRLF in same buffer
    seed4 = struct.pack('<B', 10)  # max_length
    seed4 += struct.pack('<B', 3)  # segments.len() = 3
    # Segment 1: under boundary, LF
    seed4 += struct.pack('<b', -2)  # length_offset = -2
    seed4 += struct.pack('<B', 0)  # ending = Lf
    seed4 += struct.pack('<B', ord('X'))  # fill_byte
    # Segment 2: exact boundary, CRLF
    seed4 += struct.pack('<b', 0)  # length_offset = 0
    seed4 += struct.pack('<B', 1)  # ending = Crlf
    seed4 += struct.pack('<B', ord('Y'))  # fill_byte
    # Segment 3: over boundary, LF
    seed4 += struct.pack('<b', 2)  # length_offset = +2
    seed4 += struct.pack('<B', 0)  # ending = Lf
    seed4 += struct.pack('<B', ord('Z'))  # fill_byte
    seed4 += struct.pack('<B', 1)  # test_chunked = true
    create_seed("mixed_endings", seed4)

    # Seed 5: Edge case - exact boundary with CRLF (CRLF makes it over boundary)
    seed5 = struct.pack('<B', 5)  # max_length = 5
    seed5 += struct.pack('<B', 1)  # segments.len() = 1
    seed5 += struct.pack('<b', 0)  # length_offset = 0 (5 chars)
    seed5 += struct.pack('<B', 1)  # ending = Crlf (adds 2 more bytes)
    seed5 += struct.pack('<B', ord('D'))  # fill_byte
    seed5 += struct.pack('<B', 0)  # test_chunked = false
    create_seed("boundary_crlf_overflow", seed5)

    # Seed 6: Bare CR (should not be treated as line ending)
    seed6 = struct.pack('<B', 8)  # max_length
    seed6 += struct.pack('<B', 2)  # segments.len() = 2
    # Segment 1: with bare CR
    seed6 += struct.pack('<b', -1)  # length_offset = -1
    seed6 += struct.pack('<B', 2)  # ending = Cr (bare CR)
    seed6 += struct.pack('<B', ord('E'))  # fill_byte
    # Segment 2: with proper LF
    seed6 += struct.pack('<b', 0)  # length_offset = 0
    seed6 += struct.pack('<B', 0)  # ending = Lf
    seed6 += struct.pack('<B', ord('F'))  # fill_byte
    seed6 += struct.pack('<B', 1)  # test_chunked = true
    create_seed("bare_cr_test", seed6)

    # Seed 7: No line ending (partial line)
    seed7 = struct.pack('<B', 6)  # max_length
    seed7 += struct.pack('<B', 1)  # segments.len() = 1
    seed7 += struct.pack('<b', 1)  # length_offset = +1 (over boundary)
    seed7 += struct.pack('<B', 3)  # ending = None
    seed7 += struct.pack('<B', ord('G'))  # fill_byte
    seed7 += struct.pack('<B', 0)  # test_chunked = false
    create_seed("no_ending", seed7)

    # Simple byte-based seeds for fallback
    create_seed("simple_lf", b"12345\n")
    create_seed("simple_crlf", b"12345\r\n")
    create_seed("simple_over", b"123456\n")
    create_seed("simple_mixed", b"abc\ndef\r\nghi\n")

    print("Generated seed corpus for lines_codec_boundary_case")

if __name__ == "__main__":
    main()