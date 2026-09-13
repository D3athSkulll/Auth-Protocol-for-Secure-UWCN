"""Core run metrics: anomaly detection, communication cost, and energy use."""

from __future__ import annotations

import statistics
from typing import Dict, List

from ..config import ANOMALY_THRESHOLD, BAT_uJ
from ..models.message import MessageRecord
from .paper_metrics import REFERENCE_COMM_BITS


def detect_anomalies(delay_log: List[float], threshold: float = ANOMALY_THRESHOLD) -> List[int]:
    """Return indices of delay samples that are statistical outliers
    (|z-score| > threshold)."""
    if len(delay_log) < 4:
        return []
    mean = statistics.mean(delay_log)
    stdev = statistics.stdev(delay_log)
    if stdev == 0:
        return []
    return [i for i, delay in enumerate(delay_log)
            if abs((delay - mean) / stdev) > threshold]


def communication_bits(message_records: List[MessageRecord]) -> int:
    """Total observed ciphertext size (bits) across a run, falling back to
    the paper's reference figure if no messages were recorded."""
    actual = sum(r.ciphertext_bytes * 8 for r in message_records)
    return actual if actual else REFERENCE_COMM_BITS


def energy_summary(battery: Dict[str, float], initial_uJ: float = BAT_uJ) -> Dict[str, float]:
    """Energy consumed per node (initial battery minus remaining)."""
    return {n: initial_uJ - v for n, v in battery.items()}
