"""Graph 1: static UWCN topology with the active M1-M12 path highlighted."""

from __future__ import annotations

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx

from ..models.network import build_topology_graph
from ._common import save_fig

_NODE_COLORS = {
    "U1": "#3498db", "U2": "#3498db", "S1": "#2ecc71",
    "B1": "#e67e22", "B2": "#2ecc71",
    "SAT1": "#9b59b6", "SAT2": "#9b59b6", "BS": "#f39c12",
}

_POS = {
    "U1": (0.35, 1.0), "U2": (0.65, 1.0), "S1": (0.5, 0.72),
    "B1": (0.2, 0.44), "B2": (0.8, 0.44),
    "SAT1": (0.2, 0.16), "SAT2": (0.8, 0.16), "BS": (0.5, -0.1),
}


def plot_topology(active_path, filename: str = "output_topology.png") -> None:
    graph = build_topology_graph()
    fig, ax = plt.subplots(figsize=(10, 7))
    nx.draw_networkx(graph, _POS, ax=ax,
                      node_color=[_NODE_COLORS[n] for n in graph.nodes()],
                      node_size=1100, font_size=10, font_weight="bold",
                      edge_color="#7f8c8d", width=2, with_labels=True)
    nx.draw_networkx_edges(graph, _POS, edgelist=active_path, ax=ax,
                            edge_color="#27ae60", width=3.5)
    ax.set_title("PEECC-UWCN Topology | M1-M12 Active Path\n"
                 "Evaluation layer may fall back between registered peers")
    ax.legend(handles=[
        mpatches.Patch(color="#3498db", label="UWS"),
        mpatches.Patch(color="#2ecc71", label="SUB / active relay"),
        mpatches.Patch(color="#e67e22", label="BUOY"),
        mpatches.Patch(color="#9b59b6", label="SAT"),
        mpatches.Patch(color="#f39c12", label="BS"),
    ], loc="upper left", fontsize=8)
    save_fig(fig, filename)
