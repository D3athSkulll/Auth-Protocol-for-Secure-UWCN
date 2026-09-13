"""Cryptographic primitives used by the protocol layer.

``peecc`` provides the symbolic PEECC public-key backend used for the
Scyther-mirrored NSL exchange. ``hash``, ``xor`` are its low-level building
blocks. ``aes`` is an independent AES-GCM benchmark used purely for
evaluation purposes and does not replace the protocol's own crypto.
"""

from .hash import h
from .xor import xor_stream
from .peecc import PEECCBackend, random_scalar
from .aes import aes_gcm_benchmark

__all__ = [
    "h",
    "xor_stream",
    "PEECCBackend",
    "random_scalar",
    "aes_gcm_benchmark",
]
