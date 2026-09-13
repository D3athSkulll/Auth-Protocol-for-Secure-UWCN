"""Figure generation: topology, performance (delay/energy/throughput/comm),
comparison, and battery plots."""

from .topology import plot_topology
from .performance import plot_delay, plot_energy, plot_comm_cost, plot_throughput
from .comparison import plot_comparison
from .battery import plot_battery

__all__ = [
    "plot_topology",
    "plot_delay",
    "plot_energy",
    "plot_comm_cost",
    "plot_throughput",
    "plot_comparison",
    "plot_battery",
]
