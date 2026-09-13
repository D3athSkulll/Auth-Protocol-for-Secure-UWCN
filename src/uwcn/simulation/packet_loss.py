"""Packet loss decision helper for the simulated acoustic channel."""

from __future__ import annotations

import random

from ..config import LOSS_RATE


def decide_loss(loss_rate: float = LOSS_RATE) -> bool:
    """Return True if this transmission attempt should be treated as lost."""
    return random.random() < loss_rate
