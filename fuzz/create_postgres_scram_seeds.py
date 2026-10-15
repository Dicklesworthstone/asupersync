#!/usr/bin/env python3
"""
Generate seed corpus for PostgreSQL SCRAM-SHA-256 authentication fuzzer.

Creates realistic SCRAM message structures for mutation-based fuzzing.
"""

import os
import base64
import binascii

def write_seed(filename, data):
    """Write data to a seed file."""
    path = os.path.join("seeds", "postgres_scram", filename)
    with open(path, "wb") as f:
        if isinstance(data, str):
            f.write(data.encode())
        else:
            f.write(data)

def create_sasl_mechanisms():
    """Create SASL mechanism list messages."""
    # Single mechanism
    write_seed("sasl_scram_only.bin", b"SCRAM-SHA-256\x00")

    # Multiple mechanisms
    mechanisms = b"SCRAM-SHA-256\x00SCRAM-SHA-1\x00MD5\x00"
    write_seed("sasl_multiple.bin", mechanisms)

    # Empty mechanism (invalid)
    write_seed("sasl_empty.bin", b"\x00")

    # Long mechanism name
    long_name = b"A" * 100 + b"\x00"
    write_seed("sasl_long_name.bin", long_name)

def create_server_first_messages():
    """Create SCRAM server-first messages."""
    # Valid server-first message
    valid = "r=clientnonce123servernonce456,s=MTIzNDU2Nzg5MGFiY2RlZg==,i=4096"
    write_seed("server_first_valid.txt", valid)

    # High iteration count
    high_iter = "r=cn123sn456,s=MTIzNDU2Nzg5MA==,i=100000"
    write_seed("server_first_high_iter.txt", high_iter)

    # Low iteration count (invalid)
    low_iter = "r=cn123sn456,s=MTIzNDU2Nzg5MA==,i=1"
    write_seed("server_first_low_iter.txt", low_iter)

    # Missing parts
    missing_salt = "r=cn123sn456,i=4096"
    write_seed("server_first_missing_salt.txt", missing_salt)

    missing_nonce = "s=MTIzNDU2Nzg5MA==,i=4096"
    write_seed("server_first_missing_nonce.txt", missing_nonce)

    # Invalid base64 salt
    invalid_b64 = "r=cn123sn456,s=invalid-base64!!!,i=4096"
    write_seed("server_first_invalid_b64.txt", invalid_b64)

    # Empty salt
    empty_salt = "r=cn123sn456,s=,i=4096"
    write_seed("server_first_empty_salt.txt", empty_salt)

    # Malformed format
    malformed = "malformed,message,format"
    write_seed("server_first_malformed.txt", malformed)

def create_server_final_messages():
    """Create SCRAM server-final messages."""
    # Valid server signature (32 bytes base64)
    valid_sig = base64.b64encode(b"A" * 32).decode()
    valid_final = f"v={valid_sig}"
    write_seed("server_final_valid.txt", valid_final)

    # Server error
    error_final = "e=invalid-proof"
    write_seed("server_final_error.txt", error_final)

    # Invalid signature length
    short_sig = base64.b64encode(b"A" * 16).decode()
    invalid_final = f"v={short_sig}"
    write_seed("server_final_invalid_len.txt", invalid_final)

    # Empty signature
    empty_final = "v="
    write_seed("server_final_empty.txt", empty_final)

    # Invalid base64 signature
    invalid_b64_final = "v=invalid-base64!!!"
    write_seed("server_final_invalid_b64.txt", invalid_b64_final)

def create_client_first_messages():
    """Create SCRAM client-first messages."""
    # Valid client-first message
    valid = "n,,n=testuser,r=clientnonce123"
    write_seed("client_first_valid.txt", valid)

    # Long username
    long_user = "n,,n=" + "A" * 100 + ",r=nonce123"
    write_seed("client_first_long_user.txt", long_user)

    # Empty username
    empty_user = "n,,n=,r=nonce123"
    write_seed("client_first_empty_user.txt", empty_user)

    # Special characters in username
    special_user = "n,,n=user@domain.com,r=nonce123"
    write_seed("client_first_special_user.txt", special_user)

    # Empty nonce
    empty_nonce = "n,,n=testuser,r="
    write_seed("client_first_empty_nonce.txt", empty_nonce)

def create_client_final_messages():
    """Create SCRAM client-final messages."""
    # Valid client-final message
    channel_binding = base64.b64encode(b"n,,").decode()
    client_proof = base64.b64encode(b"A" * 32).decode()
    valid = f"c={channel_binding},r=clientnonce123servernonce456,p={client_proof}"
    write_seed("client_final_valid.txt", valid)

    # Invalid proof length
    short_proof = base64.b64encode(b"A" * 16).decode()
    invalid = f"c={channel_binding},r=nonce123,p={short_proof}"
    write_seed("client_final_invalid_proof.txt", invalid)

    # Missing parts
    missing_proof = f"c={channel_binding},r=nonce123"
    write_seed("client_final_missing_proof.txt", missing_proof)

    # Invalid base64 proof
    invalid_b64_proof = f"c={channel_binding},r=nonce123,p=invalid-base64!!!"
    write_seed("client_final_invalid_b64.txt", invalid_b64_proof)

def create_edge_cases():
    """Create edge case test data."""
    # Empty data
    write_seed("empty.bin", b"")

    # Single byte
    write_seed("single_byte.bin", b"A")

    # Non-UTF8 data
    write_seed("non_utf8.bin", b"\xff\xfe\xfd")

    # Very long data
    long_data = "A" * 10000
    write_seed("very_long.txt", long_data)

    # Mixed valid/invalid characters
    mixed = "valid=data,invalid=\xff\xfe"
    write_seed("mixed_encoding.bin", mixed.encode('latin1'))

    # Base64 padding edge cases
    write_seed("base64_no_pad.txt", "SGVsbG8gV29ybGQ")  # No padding
    write_seed("base64_pad.txt", "SGVsbG8gV29ybGQ=")   # Single padding
    write_seed("base64_pad2.txt", "SGVsbG8gV29ybGQ==")  # Double padding

    # Null bytes in strings
    write_seed("null_bytes.bin", b"hello\x00world")

    # Control characters
    control_chars = "".join(chr(i) for i in range(32))
    write_seed("control_chars.bin", control_chars.encode())

def main():
    """Generate all PostgreSQL SCRAM seed files."""
    os.makedirs("seeds/postgres_scram", exist_ok=True)

    create_sasl_mechanisms()
    create_server_first_messages()
    create_server_final_messages()
    create_client_first_messages()
    create_client_final_messages()
    create_edge_cases()

    print(f"Generated {len(os.listdir('seeds/postgres_scram'))} PostgreSQL SCRAM seed files")

if __name__ == "__main__":
    main()