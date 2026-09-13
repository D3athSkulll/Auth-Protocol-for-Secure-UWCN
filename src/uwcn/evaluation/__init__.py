"""Evaluation layer: metrics, reference/paper comparisons, attack tests, and
scaling experiments built around the protocol + simulation layers."""

from .metrics import detect_anomalies, communication_bits, energy_summary
from .paper_metrics import REFERENCE_DELAY_S, REFERENCE_COMM_BITS
from .attacks import replay_test
from .scaling import scaling_data, run_rounds_with_fallback, choose_peer
from .comparison import comparison_series

__all__ = [
    "detect_anomalies",
    "communication_bits",
    "energy_summary",
    "REFERENCE_DELAY_S",
    "REFERENCE_COMM_BITS",
    "replay_test",
    "scaling_data",
    "run_rounds_with_fallback",
    "choose_peer",
    "comparison_series",
]
