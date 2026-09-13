"""Scaling experiment (delay/energy/comm/throughput vs. node count) and the
5-round resilience/fallback experiment used to exercise peer failover."""

from __future__ import annotations

import statistics
from typing import Dict, List, Optional, Set, Tuple

from ..config import AUTH_uJ
from ..models.entity import Entity
from ..simulation.delay import scale_delay


def scaling_data(sizes: List[int]) -> Tuple[List[int], List[float], List[float], List[float], List[float]]:
    """Model how mean path delay, energy, comm cost, and throughput evolve as
    the number of simulated nodes grows."""
    delays, energies, comms, throughput = [], [], [], []
    base_path = [("U1", "S1"), ("S1", "B2"), ("B2", "SAT2"), ("SAT2", "BS")]
    for n in sizes:
        path_delays = []
        for _ in range(max(1, n // 8)):
            path_delays.append(sum(scale_delay(a, b) for a, b in base_path))
        mean_delay = statistics.mean(path_delays)
        delays.append(mean_delay)
        energies.append(AUTH_uJ + n * 0.1)
        comms.append(296 + n * 10)
        throughput.append(1.0 / mean_delay if mean_delay else 0.0)
    return sizes, delays, energies, comms, throughput


def choose_peer(entities: Dict[str, Entity], current: str, candidates: List[str],
                 unavailable: Optional[Set[str]] = None) -> Optional[str]:
    """Pick the first registered, currently-available peer from ``candidates``."""
    unavailable = unavailable or set()
    for candidate in candidates:
        if candidate in entities[current].peers and candidate not in unavailable:
            return candidate
    return None


def run_rounds_with_fallback(run_ns_authentication, entities: Dict[str, Entity],
                              rounds: int = 5, verbose: bool = True) -> List[bool]:
    """Run several authentication rounds, simulating BUOY/SAT unavailability
    on certain rounds to exercise the peer-selection fallback logic.

    ``run_ns_authentication`` is a callable of signature
    ``(buoy: str, satellite: str) -> bool`` bound to a live channel/session
    context (see ``uwcn.protocol.session`` / ``scripts/run_experiments.py``).
    """
    if verbose:
        print("\n=== REPEATED EXPERIMENT: 5 ROUNDS + FALLBACK ===")

    results: List[bool] = []
    for i in range(1, rounds + 1):
        if verbose:
            print(f"\n[Round {i}]")
        unavailable_b = {"B1"} if i % 2 == 1 else set()
        unavailable_s = {"SAT1"} if i % 3 == 0 else set()

        buoy = choose_peer(entities, "S1", ["B1", "B2"], unavailable_b)
        if buoy is None:
            results.append(False)
            if verbose:
                print("No registered BUOY available")
            continue

        sat = choose_peer(entities, buoy, ["SAT1", "SAT2"], unavailable_s)
        if sat is None:
            results.append(False)
            if verbose:
                print("No registered SAT available")
            continue

        ok = run_ns_authentication(buoy, sat)
        results.append(ok)
        if verbose:
            print(f"Result: {'SUCCESS' if ok else 'FAILED'}")

    return results
