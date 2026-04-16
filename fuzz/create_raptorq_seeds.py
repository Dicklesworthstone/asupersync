#!/usr/bin/env python3
"""Create seed corpus for RaptorQ decoder fuzzer."""

import os
import struct
import random

CORPUS_DIR = "corpus/fuzz_raptorq_decoder"

def create_corpus_dir():
    os.makedirs(CORPUS_DIR, exist_ok=True)

def write_seed(name: str, data: bytes):
    with open(f"{CORPUS_DIR}/{name}", "wb") as f:
        f.write(data)
    print(f"Created seed: {name} ({len(data)} bytes)")

def encode_arbitrary_data(params_data: bytes, symbols_data: bytes) -> bytes:
    """
    Create a simple encoding for the arbitrary derive to parse.
    Format: [params_len:4][params][symbols_data]
    """
    data = struct.pack("<I", len(params_data))
    data += params_data
    data += symbols_data
    return data

def create_systematic_params(k: int, symbol_size: int, s: int = 0, h: int = 0) -> bytes:
    """Create systematic parameters for RaptorQ."""
    # Structure matches FuzzSystematicParams: k, symbol_size, s, h (all u16)
    return struct.pack("<HHHH", k, symbol_size, s, h)

def create_received_symbol(esi: int, is_source: bool, columns: list, coefficients: list, data: bytes) -> bytes:
    """Create a received symbol structure."""
    symbol_data = struct.pack("<I", esi)  # esi: u32
    symbol_data += struct.pack("B", 1 if is_source else 0)  # is_source: bool

    # columns: Vec<u16>
    symbol_data += struct.pack("<I", len(columns))  # vec length
    for col in columns:
        symbol_data += struct.pack("<H", col)

    # coefficients: Vec<u8>
    symbol_data += struct.pack("<I", len(coefficients))  # vec length
    symbol_data += bytes(coefficients)

    # data: Vec<u8>
    symbol_data += struct.pack("<I", len(data))  # vec length
    symbol_data += data

    return symbol_data

def create_symbols_vec(symbols: list) -> bytes:
    """Create a Vec<FuzzReceivedSymbol> encoding."""
    data = struct.pack("<I", len(symbols))  # vec length
    for symbol in symbols:
        data += symbol
    return data

def main():
    create_corpus_dir()

    # Basic edge cases
    write_seed("empty", b"")
    write_seed("single_byte", b"\x00")
    write_seed("minimal_params", create_systematic_params(1, 1))

    # Simple valid cases
    symbol_data = b"A" * 64

    # Single source symbol
    symbol = create_received_symbol(
        esi=0,
        is_source=True,
        columns=[0],
        coefficients=[1],
        data=symbol_data
    )
    symbols_vec = create_symbols_vec([symbol])
    params = create_systematic_params(k=1, symbol_size=64)
    write_seed("single_source", encode_arbitrary_data(params, symbols_vec))

    # Multiple source symbols
    symbols = []
    for i in range(3):
        symbol = create_received_symbol(
            esi=i,
            is_source=True,
            columns=[i],
            coefficients=[1],
            data=bytes([i] * 32)
        )
        symbols.append(symbol)

    symbols_vec = create_symbols_vec(symbols)
    params = create_systematic_params(k=3, symbol_size=32)
    write_seed("multiple_sources", encode_arbitrary_data(params, symbols_vec))

    # Mixed source and repair symbols
    symbols = []
    # Source symbols
    for i in range(2):
        symbol = create_received_symbol(
            esi=i,
            is_source=True,
            columns=[i],
            coefficients=[1],
            data=bytes([i + 1] * 16)
        )
        symbols.append(symbol)

    # Repair symbol (degree > 1)
    symbol = create_received_symbol(
        esi=10,
        is_source=False,
        columns=[0, 1],
        coefficients=[1, 1],  # XOR of symbols 0 and 1
        data=bytes([1 ^ 2] * 16)  # XOR of the data
    )
    symbols.append(symbol)

    symbols_vec = create_symbols_vec(symbols)
    params = create_systematic_params(k=2, symbol_size=16, s=1, h=0)
    write_seed("mixed_symbols", encode_arbitrary_data(params, symbols_vec))

    # Edge case parameters
    edge_cases = [
        (256, 1024, 64, 64),  # Maximum reasonable K
        (1, 1, 0, 0),         # Minimal valid
        (10, 512, 5, 5),      # Medium case with overhead
    ]

    for i, (k, symbol_size, s, h) in enumerate(edge_cases):
        params = create_systematic_params(k, symbol_size, s, h)
        # Empty symbols list
        empty_symbols = create_symbols_vec([])
        write_seed(f"edge_params_{i}_empty", encode_arbitrary_data(params, empty_symbols))

    # Invalid cases that should be rejected gracefully

    # Mismatched symbol size
    symbol = create_received_symbol(
        esi=0,
        is_source=True,
        columns=[0],
        coefficients=[1],
        data=b"wrong_size"  # 10 bytes instead of expected
    )
    symbols_vec = create_symbols_vec([symbol])
    params = create_systematic_params(k=1, symbol_size=64)  # Expects 64 bytes
    write_seed("mismatched_size", encode_arbitrary_data(params, symbols_vec))

    # Invalid ESI for source symbol
    symbol = create_received_symbol(
        esi=100,  # ESI >= K
        is_source=True,
        columns=[0],
        coefficients=[1],
        data=bytes(32)
    )
    symbols_vec = create_symbols_vec([symbol])
    params = create_systematic_params(k=5, symbol_size=32)
    write_seed("invalid_source_esi", encode_arbitrary_data(params, symbols_vec))

    # Mismatched columns/coefficients
    symbol = create_received_symbol(
        esi=0,
        is_source=True,
        columns=[0, 1, 2],  # 3 columns
        coefficients=[1, 1], # 2 coefficients - mismatch!
        data=bytes(16)
    )
    symbols_vec = create_symbols_vec([symbol])
    params = create_systematic_params(k=3, symbol_size=16)
    write_seed("mismatched_coeffs", encode_arbitrary_data(params, symbols_vec))

    # Out of bounds column references
    symbol = create_received_symbol(
        esi=5,
        is_source=False,
        columns=[0, 1, 100],  # Column 100 is out of bounds for L=5
        coefficients=[1, 1, 1],
        data=bytes(8)
    )
    symbols_vec = create_symbols_vec([symbol])
    params = create_systematic_params(k=3, symbol_size=8, s=1, h=1)  # L = 3+1+1 = 5
    write_seed("out_of_bounds_col", encode_arbitrary_data(params, symbols_vec))

    # High degree repair symbol (performance stress test)
    columns = list(range(32))  # Degree 32
    coefficients = [random.randint(1, 255) for _ in range(32)]
    symbol = create_received_symbol(
        esi=1000,
        is_source=False,
        columns=columns,
        coefficients=coefficients,
        data=bytes([42] * 128)
    )
    symbols_vec = create_symbols_vec([symbol])
    params = create_systematic_params(k=64, symbol_size=128, s=32, h=0)  # L = 96
    write_seed("high_degree", encode_arbitrary_data(params, symbols_vec))

    # Large symbol size
    large_data = bytes(range(256))  # 256 bytes of data
    symbol = create_received_symbol(
        esi=0,
        is_source=True,
        columns=[0],
        coefficients=[1],
        data=large_data
    )
    symbols_vec = create_symbols_vec([symbol])
    params = create_systematic_params(k=1, symbol_size=256)
    write_seed("large_symbol", encode_arbitrary_data(params, symbols_vec))

    # Zero coefficients
    symbol = create_received_symbol(
        esi=10,
        is_source=False,
        columns=[0, 1],
        coefficients=[0, 0],  # All zero coefficients
        data=bytes(4)
    )
    symbols_vec = create_symbols_vec([symbol])
    params = create_systematic_params(k=2, symbol_size=4)
    write_seed("zero_coefficients", encode_arbitrary_data(params, symbols_vec))

    print(f"Created {len(os.listdir(CORPUS_DIR))} seed files in {CORPUS_DIR}")

if __name__ == "__main__":
    main()