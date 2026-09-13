"""Helpers for turning the static COMPARISON reference table into plot-ready
series against prior related schemes."""

from __future__ import annotations

from typing import Dict, List

from ..config import COMPARISON


def comparison_series() -> Dict[str, Dict[str, float]]:
    """Return the raw comparison table (scheme -> {comm, uws, sub})."""
    return COMPARISON


def comparison_schemes() -> List[str]:
    return list(COMPARISON)
