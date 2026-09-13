"""PEECC point representation (5-dimensional coordinate tuple)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class PEECCPoint:
    """A point in the (symbolic) 5-dimensional PEECC coordinate space."""

    coords: Tuple[int, int, int, int, int]

    def __post_init__(self) -> None:
        if len(self.coords) != 5:
            raise ValueError("PEECC point must contain five coordinates")

    def scalar_mul(self, k: int, modulus: int) -> "PEECCPoint":
        """Scalar-multiply this point by ``k`` modulo ``modulus``."""
        return PEECCPoint(tuple((k * x) % modulus for x in self.coords))


def canonical_point(point: PEECCPoint) -> str:
    """Deterministic string encoding of a PEECC point, used for key derivation."""
    return ",".join(str(v) for v in point.coords)
