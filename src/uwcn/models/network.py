"""Topology helpers built on top of the static config (NODES/EDGES)."""

from __future__ import annotations

import networkx as nx

from ..config import EDGES


def build_topology_graph() -> "nx.Graph":
    """Build the static UWS-SUB-BUOY-SAT-BS networkx topology graph."""
    graph = nx.Graph()
    graph.add_edges_from(EDGES)
    return graph
