#!/usr/bin/env python3
"""Run the replay/freshness test and the 5-round peer-fallback resilience
experiment.

Usage:
    python scripts/run_experiments.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uwcn.crypto.peecc import PEECCBackend
from uwcn.evaluation.attacks import replay_test
from uwcn.evaluation.scaling import run_rounds_with_fallback
from uwcn.protocol.authentication import run_ns_authentication
from uwcn.protocol.initialization import initialize_entities
from uwcn.protocol.registration import register_network
from uwcn.simulation.channel import Channel


def main() -> int:
    print("=" * 78)
    print(" PEECC / UWC AUTHENTICATION -- EXPERIMENTS (REPLAY + FALLBACK)")
    print("=" * 78)

    crypto = PEECCBackend()
    entities = initialize_entities(crypto, verbose=False)
    register_network(entities, verbose=False)
    channel = Channel()
    sessions = {}

    replay_test()

    def _auth(buoy: str, satellite: str) -> bool:
        return run_ns_authentication(channel, crypto, entities, sessions,
                                      buoy=buoy, satellite=satellite, verbose=True)

    results = run_rounds_with_fallback(_auth, entities, rounds=5)

    print("\n=== EXPERIMENT SUMMARY ===")
    print(f"Rounds successful: {sum(results)}/{len(results)}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
