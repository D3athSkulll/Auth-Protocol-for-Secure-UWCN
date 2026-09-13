"""Simple bounded random-walk mobility model for mobile nodes (UWS/SUB)."""

from __future__ import annotations

import random
from typing import Dict

from ..config import NODES


class MobilityModel:
    """Tracks a scalar position offset per node, used to perturb acoustic
    distance estimates for mobile nodes."""

    def __init__(self) -> None:
        self.offsets: Dict[str, float] = {
            name: 0.0 for names in NODES.values() for name in names
        }

    def update(self, mobile_nodes=("U1", "U2", "S1"),
               step: float = 10.0, bound: float = 50.0) -> None:
        for node in mobile_nodes:
            self.offsets[node] += random.uniform(-step, step)
            self.offsets[node] = max(-bound, min(bound, self.offsets[node]))

    def offset(self, node: str) -> float:
        return self.offsets.get(node, 0.0)
