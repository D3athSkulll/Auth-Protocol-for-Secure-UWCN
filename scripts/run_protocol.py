#!/usr/bin/env python3
"""Run a single, clean M1-M12 NSL-style authentication sequence plus the
associated sensor/environment data flow.

Usage:
    python scripts/run_protocol.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uwcn.crypto.peecc import PEECCBackend
from uwcn.evaluation.metrics import communication_bits, detect_anomalies, energy_summary
from uwcn.protocol.authentication import run_ns_authentication
from uwcn.protocol.initialization import initialize_entities
from uwcn.protocol.registration import register_network
from uwcn.protocol.session import run_data_flow
from uwcn.simulation.channel import Channel


def build_system():
    crypto = PEECCBackend()
    entities = initialize_entities(crypto)
    register_network(entities)
    channel = Channel()
    sessions = {}
    return crypto, entities, channel, sessions


def main() -> int:
    print("=" * 78)
    print(" PEECC / UWC AUTHENTICATION -- SINGLE CLEAN RUN")
    print("=" * 78)

    crypto, entities, channel, sessions = build_system()

    clean = run_ns_authentication(channel, crypto, entities, sessions, "B1", "SAT1")
    print(f"\nClean M1-M12 run: {'SUCCESS' if clean else 'FAILED'}")

    data_payload = run_data_flow("B1", "SAT1")

    anomalies = detect_anomalies(channel.delay_log)
    comm_bits = communication_bits(channel.message_records)
    used = energy_summary(channel.energy.battery)

    print("\n=== RUN SUMMARY ===")
    print(f"Messages attempted     : {channel.stats.attempts}")
    print(f"Messages delivered     : {channel.stats.delivered}")
    print(f"Packets lost           : {channel.stats.lost}")
    print(f"Retransmissions        : {channel.stats.retries}")
    print(f"Communication estimate : {comm_bits} bits (observed encrypted payloads)")
    print(f"Anomalous delay hops   : {anomalies if anomalies else 'none'}")
    print("\nEnergy consumed per node:")
    for node, amount in used.items():
        print(f"  {node:5s}: {amount:.2f} uJ")
    print("\nSensor payload delivered logically to BS:")
    print(data_payload)

    print("\nScyther mapping:")
    print("  Hop 1: M1/M2/M3    = uwchop1(UWS,SUB)")
    print("  Hop 2: M4/M5/M6    = uwchop2(SUB,BUOY)")
    print("  Hop 3: M7/M8/M9    = uwchop3(BUOY,SAT)")
    print("  Hop 4: M10/M11/M12 = uwchop4(SAT,BS)")
    print("See verification/uwc_protocol.spdl for the Scyther model.")

    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
