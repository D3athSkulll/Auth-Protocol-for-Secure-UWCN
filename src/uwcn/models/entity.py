"""Network entity (UWS/SUB/BUOY/SAT/BS node) model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .point import PEECCPoint


@dataclass
class Entity:
    """A single node in the UWCN, holding its PEECC keypair and identity."""

    name: str
    role: str
    private_key: int
    public_key: PEECCPoint
    identifier: str
    peers: List[str] = field(default_factory=list)
    registered: Dict[str, str] = field(default_factory=dict)
