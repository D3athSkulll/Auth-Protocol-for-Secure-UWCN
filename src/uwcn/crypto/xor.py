"""XOR stream cipher used as the symbolic PEECC encryption envelope.

This is NOT a secure cipher; it is a lightweight, deterministic stand-in used
so the NSL-style message exchange can be exercised end-to-end in simulation.
"""

from __future__ import annotations


def xor_stream(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
