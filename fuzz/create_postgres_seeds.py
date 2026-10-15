#!/usr/bin/env python3
"""Create seed corpus for PostgreSQL wire protocol fuzzer."""

import os
import struct

CORPUS_DIR = "corpus/fuzz_postgres_wire_protocol"

def create_corpus_dir():
    os.makedirs(CORPUS_DIR, exist_ok=True)

def write_seed(name: str, data: bytes):
    with open(f"{CORPUS_DIR}/{name}", "wb") as f:
        f.write(data)
    print(f"Created seed: {name} ({len(data)} bytes)")

def create_cstring(s: str) -> bytes:
    """Create a null-terminated C string."""
    return s.encode('utf-8') + b'\x00'

def create_row_description(columns: list) -> bytes:
    """Create a PostgreSQL RowDescription message payload."""
    data = struct.pack(">h", len(columns))  # Number of fields (big endian)

    for col in columns:
        data += create_cstring(col['name'])
        data += struct.pack(">I", col['table_oid'])      # Table OID
        data += struct.pack(">h", col['column_attr'])    # Column attribute
        data += struct.pack(">I", col['type_oid'])       # Type OID
        data += struct.pack(">h", col['type_size'])      # Type size
        data += struct.pack(">i", col['type_modifier'])  # Type modifier
        data += struct.pack(">h", col['format_code'])    # Format code

    return data

def create_data_row(values: list) -> bytes:
    """Create a PostgreSQL DataRow message payload."""
    data = struct.pack(">h", len(values))  # Number of values

    for value in values:
        if value is None:
            data += struct.pack(">i", -1)  # NULL value
        else:
            value_bytes = value.encode('utf-8') if isinstance(value, str) else value
            data += struct.pack(">i", len(value_bytes))
            data += value_bytes

    return data

def create_error_response(code: str, message: str) -> bytes:
    """Create a PostgreSQL ErrorResponse message payload."""
    data = b'C' + create_cstring(code)    # Error code
    data += b'M' + create_cstring(message)  # Message
    data += b'\x00'  # End of fields
    return data

def create_parameter_description(oids: list) -> bytes:
    """Create a PostgreSQL ParameterDescription message payload."""
    data = struct.pack(">h", len(oids))  # Number of parameters
    for oid in oids:
        data += struct.pack(">I", oid)   # Parameter type OID
    return data

def main():
    create_corpus_dir()

    # Basic edge cases
    write_seed("empty", b"")
    write_seed("single_byte", b"\x00")
    write_seed("short_message", b"\x00\x01")

    # RowDescription messages
    # Empty row description
    write_seed("row_desc_empty", create_row_description([]))

    # Single column
    write_seed("row_desc_single", create_row_description([
        {
            'name': 'id',
            'table_oid': 12345,
            'column_attr': 1,
            'type_oid': 23,  # INT4
            'type_size': 4,
            'type_modifier': -1,
            'format_code': 0  # Text format
        }
    ]))

    # Multiple columns with different types
    write_seed("row_desc_multiple", create_row_description([
        {
            'name': 'id',
            'table_oid': 12345,
            'column_attr': 1,
            'type_oid': 23,  # INT4
            'type_size': 4,
            'type_modifier': -1,
            'format_code': 0
        },
        {
            'name': 'name',
            'table_oid': 12345,
            'column_attr': 2,
            'type_oid': 25,  # TEXT
            'type_size': -1,
            'type_modifier': -1,
            'format_code': 0
        },
        {
            'name': 'active',
            'table_oid': 12345,
            'column_attr': 3,
            'type_oid': 16,  # BOOL
            'type_size': 1,
            'type_modifier': -1,
            'format_code': 1  # Binary format
        }
    ]))

    # DataRow messages
    write_seed("data_row_empty", create_data_row([]))
    write_seed("data_row_single_text", create_data_row(["hello"]))
    write_seed("data_row_single_null", create_data_row([None]))
    write_seed("data_row_multiple", create_data_row([
        "123",      # INT4
        "Alice",    # TEXT
        "t"         # BOOL
    ]))
    write_seed("data_row_with_nulls", create_data_row([
        "456",
        None,
        "f"
    ]))

    # ErrorResponse messages
    write_seed("error_simple", create_error_response("42P01", "relation does not exist"))
    write_seed("error_syntax", create_error_response("42601", "syntax error"))
    write_seed("error_permission", create_error_response("42501", "permission denied"))

    # ParameterDescription messages
    write_seed("param_desc_empty", create_parameter_description([]))
    write_seed("param_desc_single", create_parameter_description([23]))  # INT4
    write_seed("param_desc_multiple", create_parameter_description([
        23,   # INT4
        25,   # TEXT
        16,   # BOOL
        701   # FLOAT8
    ]))

    # Text values for type parsing
    write_seed("text_bool_true", b"t")
    write_seed("text_bool_false", b"false")
    write_seed("text_int2", b"12345")
    write_seed("text_int4", b"-2147483648")
    write_seed("text_int8", b"9223372036854775807")
    write_seed("text_float4", b"3.14159")
    write_seed("text_float8", b"-1.23456789e-10")
    write_seed("text_bytea_hex", b"\\x48656c6c6f")
    write_seed("text_bytea_raw", b"Hello World")

    # Hex strings
    write_seed("hex_empty", b"")
    write_seed("hex_simple", b"48656c6c6f")
    write_seed("hex_uppercase", b"DEADBEEF")
    write_seed("hex_mixed", b"aAbBcC")

    # Edge cases and malformed data
    write_seed("negative_field_count", struct.pack(">h", -1))
    write_seed("huge_field_count", struct.pack(">h", 32767))
    write_seed("negative_value_count", struct.pack(">h", -1))
    write_seed("huge_value_count", struct.pack(">h", 32767))
    write_seed("negative_param_count", struct.pack(">h", -1))

    # Truncated messages
    write_seed("truncated_row_desc", create_row_description([
        {
            'name': 'test',
            'table_oid': 1,
            'column_attr': 1,
            'type_oid': 23,
            'type_size': 4,
            'type_modifier': -1,
            'format_code': 0
        }
    ])[:10])

    # Unterminated C string
    write_seed("unterminated_string", b"hello_world_no_null")

    # Invalid UTF-8
    write_seed("invalid_utf8", b"\xff\xfe")

    # Large values
    write_seed("large_string", b"A" * 1000)

    print(f"Created {len(os.listdir(CORPUS_DIR))} seed files in {CORPUS_DIR}")

if __name__ == "__main__":
    main()