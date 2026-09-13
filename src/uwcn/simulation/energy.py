"""Per-node energy/battery accounting model."""

from __future__ import annotations

from typing import Dict

from ..config import AUTH_uJ, BAT_uJ, NODES, RX_uJ, TX_uJ

_COSTS = {"auth": AUTH_uJ, "tx": TX_uJ, "rx": RX_uJ}


class EnergyModel:
    """Tracks remaining battery (in microjoules) per node."""

    def __init__(self, initial_uJ: float = BAT_uJ) -> None:
        self.initial_uJ = initial_uJ
        self.battery: Dict[str, float] = {
            name: initial_uJ for names in NODES.values() for name in names
        }

    def use(self, node: str, operation: str) -> None:
        if operation not in _COSTS:
            raise ValueError(f"unknown energy operation: {operation}")
        self.battery[node] -= _COSTS[operation]

    def used(self) -> Dict[str, float]:
        return {n: self.initial_uJ - v for n, v in self.battery.items()}

    def remaining_pct(self, node: str) -> float:
        return 100.0 * self.battery[node] / self.initial_uJ
