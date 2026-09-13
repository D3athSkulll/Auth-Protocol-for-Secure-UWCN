"""Symbolic PEECC public-key backend.

IMPORTANT: This file is intentionally kept as a runnable protocol/evaluation
model, not a production cryptographic implementation. The paper gives a
PEECC 5-dimensional representation but does not provide a complete
executable 5-D group law and public-key-encryption construction. This
backend is therefore an isolated symbolic/simulation abstraction -- do not
interpret its XOR envelope as deployable security.
"""

from __future__ import annotations

import hashlib
import os
from typing import Tuple

from ..config import D, GENERATOR, P
from ..models.point import PEECCPoint, canonical_point
from .xor import xor_stream


def random_scalar() -> int:
    return int.from_bytes(os.urandom(32), "big") % P or 1


class PEECCBackend:
    """Symbolic PEECC key generation, key agreement, and XOR-envelope
    encryption/decryption, mirroring the architecture used by the protocol
    layer for the M1-M12 NSL-style exchange."""

    def __init__(self, prime: int = P, d: int = D) -> None:
        self.p = prime
        self.d = d
        self.generator = PEECCPoint(tuple(x % prime for x in GENERATOR))

    def generate_keypair(self) -> Tuple[int, PEECCPoint]:
        private = random_scalar()
        return private, self.generator.scalar_mul(private, self.p)

    def shared_point(self, private: int, peer_public: PEECCPoint) -> PEECCPoint:
        return peer_public.scalar_mul(private, self.p)

    def derive_key(self, point: PEECCPoint) -> bytes:
        return hashlib.sha256(canonical_point(point).encode()).digest()

    def encrypt(self, sender_private: int, receiver_public: PEECCPoint,
                plaintext: str) -> bytes:
        point = self.shared_point(sender_private, receiver_public)
        return xor_stream(plaintext.encode(), self.derive_key(point))

    def decrypt(self, receiver_private: int, sender_public: PEECCPoint,
                ciphertext: bytes) -> str:
        point = self.shared_point(receiver_private, sender_public)
        return xor_stream(ciphertext, self.derive_key(point)).decode()
