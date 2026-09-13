"""Graph 5: computational cost and communication overhead vs. prior schemes."""

from __future__ import annotations

import matplotlib.pyplot as plt

from ..evaluation.comparison import comparison_schemes, comparison_series
from ._common import save_fig


def plot_comparison(filename: str = "output_comparison.png") -> None:
    comparison = comparison_series()
    schemes = comparison_schemes()
    x = list(range(len(schemes)))
    width = 0.35

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    axes[0].bar([v - width / 2 for v in x],
                [comparison[s]["uws"] for s in schemes], width,
                label="UWS/BS")
    axes[0].bar([v + width / 2 for v in x],
                [comparison[s]["sub"] for s in schemes], width,
                label="SUB/SAT", alpha=0.55)
    axes[0].set_yscale("log")
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(schemes, rotation=20)
    axes[0].set_ylabel("Time (ms)")
    axes[0].set_title("Computational Cost")
    axes[0].legend(fontsize=8)

    axes[1].bar(schemes, [comparison[s]["comm"] for s in schemes])
    axes[1].set_ylabel("Bits")
    axes[1].set_title("Communication Overhead")
    axes[1].tick_params(axis="x", rotation=20)

    save_fig(fig, filename)
