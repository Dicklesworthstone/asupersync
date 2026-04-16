#!/usr/bin/env python3
"""
Generate seed corpus for TLS message parsing fuzzer.

This creates realistic TLS message structures that the fuzzer can use
as starting points for mutation-based fuzzing.
"""

import struct
import os
import base64

def write_seed(filename, data):
    """Write binary data to a seed file."""
    path = os.path.join("seeds", "tls", filename)
    with open(path, "wb") as f:
        f.write(data)

def create_tls_handshake_header(msg_type, length, body):
    """Create TLS handshake message with header."""
    header = struct.pack("!BH", msg_type, length >> 8) + struct.pack("!B", length & 0xFF)
    return header + body

def create_client_hello():
    """Create a basic ClientHello message."""
    # Protocol version: TLS 1.3
    version = struct.pack("!H", 0x0304)

    # Random (32 bytes)
    random = b"A" * 32

    # Session ID (empty)
    session_id_len = struct.pack("!B", 0)
    session_id = b""

    # Cipher suites (2 common ones)
    cipher_suites = struct.pack("!H", 4)  # length
    cipher_suites += struct.pack("!HH", 0x1301, 0x1302)  # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384

    # Compression methods (none)
    compression_methods = struct.pack("!BB", 1, 0)

    # Extensions (basic SNI)
    sni_data = struct.pack("!BH", 0, 11) + b"example.com"  # hostname type, length, hostname
    sni_list = struct.pack("!H", len(sni_data)) + sni_data
    sni_ext = struct.pack("!HH", 0, len(sni_list)) + sni_list  # SNI extension type, length

    extensions_len = struct.pack("!H", len(sni_ext))
    extensions = extensions_len + sni_ext

    body = version + random + session_id_len + session_id + cipher_suites + compression_methods + extensions
    return create_tls_handshake_header(1, len(body), body)  # ClientHello = 1

def create_server_hello():
    """Create a basic ServerHello message."""
    # Protocol version: TLS 1.3
    version = struct.pack("!H", 0x0304)

    # Random (32 bytes)
    random = b"B" * 32

    # Session ID (empty for TLS 1.3)
    session_id_len = struct.pack("!B", 0)
    session_id = b""

    # Cipher suite (single choice)
    cipher_suite = struct.pack("!H", 0x1301)  # TLS_AES_128_GCM_SHA256

    # Compression method (none)
    compression = struct.pack("!B", 0)

    # Extensions (empty)
    extensions_len = struct.pack("!H", 0)

    body = version + random + session_id_len + session_id + cipher_suite + compression + extensions_len
    return create_tls_handshake_header(2, len(body), body)  # ServerHello = 2

def create_certificate_message():
    """Create a Certificate handshake message."""
    # Certificate request context (empty for server cert)
    cert_request_context = struct.pack("!B", 0)

    # Single certificate (minimal self-signed cert)
    cert_der = bytes.fromhex(
        "308201223081c9a003020102020900f2b99b1be0b0671a300a06082a8648ce3d040302300e310c300a06035504030c03666f6f301e170d3234303130313030303030305a170d3235303130313030303030305a300e310c300a06035504030c03666f6f3059301306072a8648ce3d020106082a8648ce3d03010703420004aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffa3533051301d0603551d0e041604149999888877776666555544443333222211110000ffff30300603551d11042930278207666f6f2e636f6d82096c6f63616c686f737487047f00000182047f000001300a06082a8648ce3d04030203480030450220123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0022100fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    )

    # Certificate entry
    cert_len = struct.pack("!H", len(cert_der) >> 8) + struct.pack("!B", len(cert_der) & 0xFF)
    cert_entry = cert_len + cert_der
    cert_extensions = struct.pack("!H", 0)  # No extensions
    cert_entry += cert_extensions

    # Certificate list
    cert_list_len = struct.pack("!H", len(cert_entry) >> 8) + struct.pack("!B", len(cert_entry) & 0xFF)
    cert_list = cert_list_len + cert_entry

    body = cert_request_context + cert_list
    return create_tls_handshake_header(11, len(body), body)  # Certificate = 11

def create_pem_certificate():
    """Create a PEM-encoded certificate for testing."""
    cert_pem = """-----BEGIN CERTIFICATE-----
MIIBIjCBzaADAgECAgkA8rmbG+CwZxowCgYIKoZIzj0EAwIwDjEMMAoGA1UEAwwD
Zm9vMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowDjEMMAoGA1UEAwwD
Zm9vMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqrvM3e7/ABEiM0RVZneImaq7
zN3u/wARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7/ABEiM0RVZneImaNT
MFEwHQYDVR0OBBYEFJmZiIh3dnZlVUREM2IhEQAP/zAwBgNVHREEKTAnggdmb28u
Y29tgglsb2NhbGhvc3SHBH8AAAGCBH8AAAEwCgYIKoZIzj0EAwIDSAAwRQIgEjRW
eJq83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vACIQD+3LqYdlQyEP7cuph2VDIQ
/ty6mHZUMhD+3LqYdlQyEA==
-----END CERTIFICATE-----"""
    return cert_pem.encode()

def create_pem_private_key():
    """Create a PEM-encoded private key for testing."""
    key_pem = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqqkUYQQBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBKhRANCAAQEjRWeJq83vASNFZ4mrze8BI0V
niavN7wEjRWeJq83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8
-----END PRIVATE KEY-----"""
    return key_pem.encode()

def create_malformed_messages():
    """Create various malformed TLS messages for edge case testing."""
    messages = []

    # Truncated handshake header
    messages.append(b"\x01\x00")

    # Handshake with length mismatch
    messages.append(b"\x01\x00\x00\x10" + b"A" * 5)  # Says 16 bytes but only has 5

    # Oversized length field
    messages.append(b"\x01\xFF\xFF\xFF")

    # ClientHello with truncated random
    messages.append(b"\x01\x00\x00\x20\x03\x04" + b"A" * 10)  # Truncated random

    # Certificate with invalid DER
    cert_data = b"\x30\x82\xFF\xFF"  # Invalid ASN.1 length encoding
    cert_len = struct.pack("!H", len(cert_data) >> 8) + struct.pack("!B", len(cert_data) & 0xFF)
    cert_list = struct.pack("!H", (len(cert_data) + 3) >> 8) + struct.pack("!B", (len(cert_data) + 3) & 0xFF)
    invalid_cert = create_tls_handshake_header(11, len(cert_list + cert_len + cert_data),
                                              cert_list + cert_len + cert_data)
    messages.append(invalid_cert)

    return messages

def main():
    """Generate all TLS seed files."""
    os.makedirs("seeds/tls", exist_ok=True)

    # Valid TLS handshake messages
    write_seed("client_hello.bin", create_client_hello())
    write_seed("server_hello.bin", create_server_hello())
    write_seed("certificate.bin", create_certificate_message())

    # Certificate and key data
    write_seed("cert.pem", create_pem_certificate())
    write_seed("key.pem", create_pem_private_key())

    # Raw certificate DER
    cert_der = bytes.fromhex(
        "308201223081c9a003020102020900f2b99b1be0b0671a300a06082a8648ce3d040302300e310c300a06035504030c03666f6f301e170d3234303130313030303030305a170d3235303130313030303030305a300e310c300a06035504030c03666f6f3059301306072a8648ce3d020106082a8648ce3d03010703420004aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffa3533051301d0603551d0e041604149999888877776666555544443333222211110000ffff30300603551d11042930278207666f6f2e636f6d82096c6f63616c686f737487047f00000182047f000001300a06082a8648ce3d04030203480030450220123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0022100fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    )
    write_seed("cert.der", cert_der)

    # Edge cases and malformed data
    malformed = create_malformed_messages()
    for i, msg in enumerate(malformed):
        write_seed(f"malformed_{i}.bin", msg)

    # Empty and minimal cases
    write_seed("empty.bin", b"")
    write_seed("single_byte.bin", b"\x01")
    write_seed("handshake_header_only.bin", b"\x01\x00\x00\x00")

    # Base64 test data for pin validation
    valid_b64_hash = base64.b64encode(b"A" * 32).decode()
    invalid_b64 = "not valid base64!!!"
    wrong_length_b64 = base64.b64encode(b"A" * 16).decode()

    write_seed("valid_b64_hash.txt", valid_b64_hash.encode())
    write_seed("invalid_b64.txt", invalid_b64.encode())
    write_seed("wrong_length_b64.txt", wrong_length_b64.encode())

    print(f"Generated {len(os.listdir('seeds/tls'))} TLS seed files")

if __name__ == "__main__":
    main()