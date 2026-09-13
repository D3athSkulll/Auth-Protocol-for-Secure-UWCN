"""Message-level helpers: nonces, freshness checks, and PEECC field framing."""

from __future__ import annotations

import os
import time
from typing import Dict, List

from ..config import TSW
from ..crypto.peecc import PEECCBackend
from ..models.entity import Entity


def new_nonce() -> int:
    return int.from_bytes(os.urandom(8), "big")


def check_timestamp(t_sent: float, t_recv: float, window: float = TSW) -> bool:
    return abs(t_recv - t_sent) < window


def encrypt_fields(crypto: PEECCBackend, entities: Dict[str, Entity],
                    sender: str, receiver: str, fields: List[str]) -> bytes:
    return crypto.encrypt(
        entities[sender].private_key,
        entities[receiver].public_key,
        "|".join(fields),
    )


def decrypt_fields(crypto: PEECCBackend, entities: Dict[str, Entity],
                    sender: str, receiver: str, ciphertext: bytes) -> List[str]:
    plaintext = crypto.decrypt(
        entities[receiver].private_key,
        entities[sender].public_key,
        ciphertext,
    )
    return plaintext.split("|")
