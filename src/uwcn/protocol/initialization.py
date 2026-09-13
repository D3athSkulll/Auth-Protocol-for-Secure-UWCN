"""System initialization: keypair generation and identity assignment for
every entity (UWS/SUB/BUOY/SAT/BS) in the network."""

from __future__ import annotations

from typing import Dict

from ..config import NODES, PEERS
from ..crypto.hash import h
from ..crypto.peecc import PEECCBackend
from ..models.entity import Entity
from ..models.point import canonical_point


def initialize_entities(crypto: PEECCBackend, verbose: bool = True) -> Dict[str, Entity]:
    """Generate a PEECC keypair and identifier for every node and wire up the
    static peer adjacency. Mirrors the original ``_initialize_system``."""
    if verbose:
        print("\n=== SYSTEM INITIALISATION ===")

    entities: Dict[str, Entity] = {}
    for role, names in NODES.items():
        for name in names:
            private, public = crypto.generate_keypair()
            identifier = h(canonical_point(public), name)
            entities[name] = Entity(name, role, private, public, identifier)

    for name, plist in PEERS.items():
        entities[name].peers = plist

    if verbose:
        for e in entities.values():
            print(f"{e.name:5s} role={e.role:5s} ID={e.identifier[:20]}...")

    return entities
