"""Registration phase: RID/THETA derivation and pairwise registration links."""

from __future__ import annotations

from typing import Dict, Set

from ..config import DIRECT_LINKS
from ..crypto.hash import h
from ..models.entity import Entity
from ..models.point import canonical_point


def register_entity(entities: Dict[str, Entity], name: str,
                     registration_set: Set[str], verbose: bool = True) -> None:
    e = entities[name]
    rid = h(e.identifier, canonical_point(e.public_key), e.private_key)
    theta = h(rid, canonical_point(e.public_key))
    e.registered["RID"] = rid
    e.registered["THETA"] = theta
    registration_set.add(rid)
    if verbose:
        print(f"[REGISTERED] {name:5s} RID={rid[:16]}...")


def _register_link(entities: Dict[str, Entity], a: str, b: str) -> bool:
    ea, eb = entities[a], entities[b]
    theta = h(ea.registered["RID"], canonical_point(ea.public_key))
    if theta != ea.registered["THETA"]:
        return False
    eb.registered[a] = ea.registered["RID"]
    eb.registered[a + ":THETA"] = theta
    return True


def register_network(entities: Dict[str, Entity], verbose: bool = True) -> Set[str]:
    """Register every entity and every direct link, returning the resulting
    registration set (set of unique RIDs)."""
    if verbose:
        print("\n=== REGISTRATION PHASE ===")

    registration_set: Set[str] = set()
    for name in entities:
        register_entity(entities, name, registration_set, verbose=verbose)

    for a, b in DIRECT_LINKS:
        _register_link(entities, a, b)

    if verbose:
        print(f"Registration set R: {len(registration_set)} unique RIDs")

    return registration_set
