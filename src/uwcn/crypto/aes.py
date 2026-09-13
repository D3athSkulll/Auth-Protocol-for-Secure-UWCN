"""AES-GCM timing benchmark.

This is an independent evaluation micro-benchmark only -- it does NOT
replace or participate in the protocol's own (PEECC/XOR) message crypto.
"""

from __future__ import annotations

import os
import time
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - optional dependency
    AESGCM = None


def aes_gcm_benchmark() -> Optional[float]:
    """Encrypt+decrypt a small fixed payload once and return the elapsed time
    in seconds, or ``None`` if the ``cryptography`` package is unavailable."""
    if AESGCM is None:
        return None
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    payload = b"UWC-AES-GCM-BENCHMARK"
    t0 = time.perf_counter()
    ct = aes.encrypt(nonce, payload, None)
    aes.decrypt(nonce, ct, None)
    return time.perf_counter() - t0
