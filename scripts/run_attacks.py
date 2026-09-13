#!/usr/bin/env python3
"""Run attack-oriented evaluation: replay/freshness test plus delay-anomaly
detection over a batch of authentication attempts.

Usage:
    python scripts/run_attacks.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uwcn.crypto.peecc import PEECCBackend
from uwcn.evaluation.attacks import replay_test
from uwcn.evaluation.metrics import detect_anomalies
from uwcn.protocol.authentication import run_ns_authentication
from uwcn.protocol.initialization import initialize_entities
from uwcn.protocol.registration import register_network
from uwcn.simulation.channel import Channel


def main() -> int:
    print("=" * 78)
    print(" PEECC / UWC AUTHENTICATION -- ATTACK EVALUATION")
    print("=" * 78)

    crypto = PEECCBackend()
    entities = initialize_entities(crypto, verbose=False)
    register_network(entities, verbose=False)
    channel = Channel()
    sessions = {}

    replay_accepted = replay_test()

    # Run a handful of authentication attempts to build up a delay sample
    # large enough for anomaly detection to be meaningful.
    for _ in range(5):
        run_ns_authentication(channel, crypto, entities, sessions,
                               "B1", "SAT1", verbose=False)

    anomalies = detect_anomalies(channel.delay_log)

    print("\n=== ATTACK EVALUATION SUMMARY ===")
    print(f"Replay attack accepted : {replay_accepted} (should be False)")
    print(f"Delay samples observed : {len(channel.delay_log)}")
    print(f"Anomalous delay hops   : {anomalies if anomalies else 'none'}")

    return 1 if replay_accepted else 0


if __name__ == "__main__":
    raise SystemExit(main())
