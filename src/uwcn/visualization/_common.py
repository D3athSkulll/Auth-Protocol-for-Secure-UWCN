"""Shared plotting utilities (figure saving convention)."""

from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def save_fig(fig, filename: str, verbose: bool = True) -> None:
    fig.tight_layout()
    fig.savefig(filename, dpi=150, bbox_inches="tight")
    plt.close(fig)
    if verbose:
        print(f"Saved: {filename}")
