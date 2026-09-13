#!/usr/bin/env python3
"""Run the full pipeline once and produce all seven output_*.png figures in
outputs/figures/.

Usage:
    python scripts/generate_plots.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from uwcn.config import SCALE_SIZES
from uwcn.crypto.peecc import PEECCBackend
from uwcn.evaluation.scaling import scaling_data
from uwcn.protocol.authentication import run_ns_authentication
from uwcn.protocol.initialization import initialize_entities
from uwcn.protocol.registration import register_network
from uwcn.simulation.channel import Channel
from uwcn.visualization.battery import plot_battery
from uwcn.visualization.comparison import plot_comparison
from uwcn.visualization.performance import (
    plot_comm_cost,
    plot_delay,
    plot_energy,
    plot_throughput,
)
from uwcn.visualization.topology import plot_topology


def main() -> int:
    print("=" * 78)
    print(" PEECC / UWC AUTHENTICATION -- FIGURE GENERATION")
    print("=" * 78)

    out_dir = ROOT / "outputs" / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chdir(out_dir)

    crypto = PEECCBackend()
    entities = initialize_entities(crypto, verbose=False)
    register_network(entities, verbose=False)
    channel = Channel()
    sessions = {}
    run_ns_authentication(channel, crypto, entities, sessions, "B1", "SAT1", verbose=False)

    ns, delays, energies, comms, throughput = scaling_data(SCALE_SIZES)

    active_path = [("U1", "S1"), ("S1", "B2"), ("B2", "SAT2"), ("SAT2", "BS")]
    plot_topology(active_path)
    plot_delay(ns, delays)
    plot_energy(ns, energies)
    plot_comm_cost(ns, comms)
    plot_comparison()
    plot_throughput(ns, throughput)
    plot_battery(channel.energy.battery)

    print(f"\nAll figures written to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
