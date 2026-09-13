"""Generic hashing helper used throughout the protocol (RID/THETA/session IDs)."""

from __future__ import annotations

import hashlib


def h(*parts: object) -> str:
    """SHA-256 hash of the ``|``-joined string representation of ``parts``."""
    material = "|".join(str(x) for x in parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()
