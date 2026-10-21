#!/usr/bin/env python3
"""Independent OpenSSL peer for the opt-in native RFC 9266 interoperability lane.

Requires Python 3 and pyOpenSSL >= 25.2 with OpenSSL TLS 1.3 support. Missing
prerequisites are errors, not skipped tests. This helper always listens on a
loopback ephemeral TCP port; its TLS role is independent of its TCP role.
"""

import argparse
import select
import socket
import sys
import time
from pathlib import Path

from OpenSSL import SSL, crypto

LABEL = b"EXPORTER-Channel-Binding"
MAGIC = b"RFC9266\x00"
ALPN = b"asupersync-exporter-test"
TLS13_CIPHERS = (
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
)
TLS12_CIPHER = "ECDHE-RSA-AES128-GCM-SHA256"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def context(role, version, cipher):
    directory = Path(__file__).resolve().parent
    ctx = SSL.Context(SSL.TLS_METHOD)
    protocol = SSL.TLS1_3_VERSION if version == 13 else SSL.TLS1_2_VERSION
    ctx.set_min_proto_version(protocol)
    ctx.set_max_proto_version(protocol)
    if version == 13:
        require(cipher in TLS13_CIPHERS, "unsupported TLS 1.3 cipher")
        ctx.set_tls13_ciphersuites(cipher.encode("ascii"))
    else:
        require(cipher == TLS12_CIPHER, "unsupported TLS 1.2 cipher")
        ctx.set_cipher_list(cipher.encode("ascii"))
    if role == "server":
        ctx.use_certificate_chain_file(str(directory / "server.crt"))
        ctx.use_privatekey_file(str(directory / "server.key"))
        ctx.check_privatekey()

        def choose_alpn(_connection, offered):
            require(ALPN in offered, "missing interoperability ALPN")
            return ALPN

        ctx.set_alpn_select_callback(choose_alpn)
    else:
        ctx.load_verify_locations(str(directory / "server.crt"))
        # Preserve OpenSSL's verification verdict; never accept a failed chain.
        ctx.set_verify(SSL.VERIFY_PEER, lambda _c, _cert, _errno, _depth, ok: ok)
        ctx.set_alpn_protos([ALPN])
    return ctx


def drive(connection, deadline, operation):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("OpenSSL peer deadline exceeded")
        try:
            return operation()
        except SSL.WantReadError:
            ready, _, _ = select.select([connection], [], [], remaining)
            if not ready:
                raise TimeoutError("OpenSSL peer read deadline exceeded")
        except SSL.WantWriteError:
            _, ready, _ = select.select([], [connection], [], remaining)
            if not ready:
                raise TimeoutError("OpenSSL peer write deadline exceeded")


def receive(connection, deadline, size):
    data = bytearray()
    while len(data) < size:
        part = drive(connection, deadline, lambda: connection.recv(size - len(data)))
        require(bool(part), "EOF before the interoperability frame completed")
        data.extend(part)
    return bytes(data)


def send(connection, deadline, data):
    offset = 0
    while offset < len(data):
        count = drive(connection, deadline, lambda: connection.send(data[offset:]))
        require(count > 0, "OpenSSL write made no progress")
        offset += count


def close_tls(connection, deadline):
    # First call sends close_notify; the second normally waits for its peer.
    for _ in range(4):
        if drive(connection, deadline, connection.shutdown):
            return
    raise RuntimeError("OpenSSL did not complete reciprocal close_notify")


def serve(role, version, cipher, deadline_seconds=15):
    ctx = context(role, version, cipher)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(deadline_seconds)
        print(f"READY 127.0.0.1:{listener.getsockname()[1]}", flush=True)
        transport, _ = listener.accept()
        with transport:
            transport.setblocking(False)
            tls = SSL.Connection(ctx, transport)
            if role == "server":
                tls.set_accept_state()
            else:
                tls.set_connect_state()
                tls.set_tlsext_host_name(b"localhost")
            deadline = time.monotonic() + deadline_seconds
            drive(tls, deadline, tls.do_handshake)
            expected_version = "TLSv1.3" if version == 13 else "TLSv1.2"
            require(tls.get_protocol_version_name() == expected_version, "protocol downgrade")
            require(tls.get_cipher_name() == cipher, "unexpected cipher suite")
            require(tls.get_alpn_proto_negotiated() == ALPN, "unexpected ALPN")
            if role == "client":
                # Also pin the exact localhost test certificate. pyOpenSSL's
                # chain check alone does not perform DNS-name verification.
                pem = (Path(__file__).resolve().parent / "server.crt").read_bytes()
                expected = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
                peer = tls.get_peer_certificate()
                require(peer is not None, "server omitted its certificate")
                require(
                    crypto.dump_certificate(crypto.FILETYPE_ASN1, peer)
                    == crypto.dump_certificate(crypto.FILETYPE_ASN1, expected),
                    "server is not the pinned localhost fixture",
                )

            # Independent OpenSSL derivation, not bytes supplied by the Rust peer.
            binding = tls.export_keying_material(LABEL, 32, b"")
            wrong_label = tls.export_keying_material(LABEL + b"-wrong", 32, b"")
            wrong_context = tls.export_keying_material(LABEL, 32, b"not-empty")
            require(len(binding) == 32, "invalid exporter length")
            require(binding != wrong_label and binding != wrong_context, "invalid controls")
            send(tls, deadline, MAGIC + bytes([version]) + binding + wrong_label + wrong_context)
            expected_ack = b"BIND" + binding if version == 13 else b"REJECTED"
            require(receive(tls, deadline, len(expected_ack)) == expected_ack,
                    "public Rust exporter disagrees with OpenSSL, or TLS 1.2 was accepted")
            send(tls, deadline, b"DONE")
            close_tls(tls, deadline)
    print(f"OK {expected_version} {cipher}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("client", "server"), required=True)
    parser.add_argument("--version", type=int, choices=(12, 13), required=True)
    parser.add_argument("--cipher", required=True)
    args = parser.parse_args()
    print(SSL.SSLeay_version(SSL.SSLEAY_VERSION).decode("ascii"), file=sys.stderr)
    serve(args.role, args.version, args.cipher)


if __name__ == "__main__":
    main()
