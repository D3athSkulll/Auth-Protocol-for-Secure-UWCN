"""Graphs 2, 3, 4, 6: delay, energy, communication cost, and throughput vs.
network scale."""

from __future__ import annotations

from typing import List

import matplotlib.pyplot as plt

from ..evaluation.comparison import comparison_series
from ..evaluation.paper_metrics import (
    REFERENCE_DELAY_S,
    REFERENCE_ENERGY_UJ_REF22,
    REFERENCE_ENERGY_UJ_REF24,
)
from ._common import save_fig


def plot_delay(ns: List[int], delays: List[float],
               filename: str = "output_delay.png") -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(ns, delays, marker="o", lw=2, label="M1-M12 path delay")
    ax.axhline(REFERENCE_DELAY_S, ls="--", lw=1.5,
               label=f"Reference {int(REFERENCE_DELAY_S * 1000)} ms")
    ax.set_title("Authentication Path Delay vs Number of Nodes")
    ax.set_xlabel("Number of Nodes")
    ax.set_ylabel("Mean Delay (s)")
    ax.legend()
    ax.grid(alpha=0.4)
    save_fig(fig, filename)


def plot_energy(ns: List[int], energies: List[float],
                 filename: str = "output_energy.png") -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(ns, energies, marker="o", lw=2, label="Evaluation energy model")
    ax.axhline(REFERENCE_ENERGY_UJ_REF24, ls="--", lw=1.5, label="Ref [24] reference")
    ax.axhline(REFERENCE_ENERGY_UJ_REF22, ls=":", lw=1.5, label="Ref [22] reference")
    ax.set_title("Energy Consumption vs Number of Nodes")
    ax.set_xlabel("Number of Nodes")
    ax.set_ylabel("Energy per Auth Cycle (uJ)")
    ax.legend()
    ax.grid(alpha=0.4)
    save_fig(fig, filename)


def plot_comm_cost(ns: List[int], comms: List[float],
                    filename: str = "output_comm_cost.png") -> None:
    comparison = comparison_series()
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(ns, comms, marker="o", lw=2, label="Evaluation estimate")
    for ref in ("Ref [21]", "Ref [22]", "Ref [23]"):
        ax.plot(ns, [comparison[ref]["comm"] + n * 10 for n in ns], "--",
                lw=1.1, label=ref)
    ax.set_title("Communication Cost vs Number of Nodes")
    ax.set_xlabel("Number of Nodes")
    ax.set_ylabel("Bits")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.4)
    save_fig(fig, filename)


def plot_throughput(ns: List[int], throughput: List[float],
                     filename: str = "output_throughput.png") -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(ns, throughput, marker="s", lw=2, label="1 / mean path delay")
    ax.set_title("Authentication Throughput vs Network Scale")
    ax.set_xlabel("Number of Nodes")
    ax.set_ylabel("Authentications per Second")
    ax.legend()
    ax.grid(alpha=0.4)
    save_fig(fig, filename)
