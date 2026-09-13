"""Graph 7: remaining battery percentage per node."""

from __future__ import annotations

from typing import Dict

import matplotlib.pyplot as plt

from ..config import BAT_uJ
from ._common import save_fig


def plot_battery(battery: Dict[str, float], initial_uJ: float = BAT_uJ,
                  filename: str = "output_battery.png") -> None:
    labels = list(battery)
    percentages = [100 * battery[n] / initial_uJ for n in labels]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(labels, percentages)
    for bar, pct in zip(bars, percentages):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                f"{pct:.2f}%", ha="center", va="bottom", fontsize=8)
    ax.set_ylim(0, 105)
    ax.axhline(90, ls="--", lw=1, label="90% threshold")
    ax.set_title("Battery Remaining per Node")
    ax.set_ylabel("Battery Remaining (%)")
    ax.legend()
    ax.grid(axis="y", alpha=0.4)
    save_fig(fig, filename)
