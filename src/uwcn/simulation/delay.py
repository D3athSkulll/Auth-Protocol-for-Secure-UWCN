"""Thorp-based underwater acoustic propagation/delay model."""

from __future__ import annotations

import random
from typing import Dict, Tuple

from ..config import ACOUSTIC_FREQ_KHZ, DISTS, SOUND_MPS


def thorp_db_per_km(freq_khz: float) -> float:
    """Thorp's empirical underwater acoustic absorption formula (dB/km)."""
    f2 = freq_khz ** 2
    return (0.11 * f2 / (1 + f2)
            + 44 * f2 / (4100 + f2)
            + 2.75e-4 * f2 + 0.003)


def _lookup_distance(sender: str, receiver: str,
                      mobility_offset: float = 0.0) -> float:
    key = (sender, receiver) if (sender, receiver) in DISTS else (receiver, sender)
    distance = DISTS.get(key, 500) + abs(mobility_offset)
    return max(10.0, distance)


def acoustic_delay(sender: str, receiver: str, mobility_offset: float = 0.0) -> float:
    """End-to-end delay estimate (propagation + absorption + multipath jitter),
    in seconds, for a message travelling from ``sender`` to ``receiver``."""
    distance = _lookup_distance(sender, receiver, mobility_offset)
    propagation = distance / SOUND_MPS
    absorption = thorp_db_per_km(ACOUSTIC_FREQ_KHZ) * (distance / 1000) * 1e-4
    multipath = abs(random.gauss(0, 0.005))
    return propagation + absorption + multipath


def scale_delay(sender: str, receiver: str) -> float:
    """Delay estimate used by the scaling experiment, with wider distance
    jitter to emulate a larger, less predictable deployment."""
    key = (sender, receiver) if (sender, receiver) in DISTS else (receiver, sender)
    distance = max(10.0, DISTS.get(key, 500) + random.uniform(-20, 20))
    prop = distance / SOUND_MPS
    absorption = thorp_db_per_km(ACOUSTIC_FREQ_KHZ) * distance / 1000 * 1e-4
    multipath = abs(random.gauss(0, 0.005))
    return prop + absorption + multipath
