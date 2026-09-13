"""
Central configuration for the UWCN / PEECC simulation and evaluation harness.

All "magic numbers" from the original single-file prototype live here so that
every other module (crypto, protocol, simulation, evaluation, visualization)
imports its constants from a single source of truth.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Cryptographic / PEECC backend parameters
# ---------------------------------------------------------------------------

HASH_NAME = "sha256"
P = 2**255 - 19
D = 2
GENERATOR = (5, 7, 11, 13, 17)

# ---------------------------------------------------------------------------
# Protocol timing
# ---------------------------------------------------------------------------

TSW = 5.0  # timestamp validity window (seconds) for freshness checks

# ---------------------------------------------------------------------------
# Acoustic channel / evaluation parameters
# ---------------------------------------------------------------------------

SOUND_MPS = 1500.0
ACOUSTIC_FREQ_KHZ = 25.0
LOSS_RATE = 0.15
MAX_RETRY = 3

# ---------------------------------------------------------------------------
# Energy / battery model
# ---------------------------------------------------------------------------

BAT_uJ = 3_300_000.0
AUTH_uJ = 48.8
TX_uJ = 50.0
RX_uJ = 36.0

# ---------------------------------------------------------------------------
# Scaling experiment / anomaly detection
# ---------------------------------------------------------------------------

SCALE_SIZES = [10, 20, 50, 100, 150, 200]
ANOMALY_THRESHOLD = 2.5

# ---------------------------------------------------------------------------
# Topology: physical distances (meters), retained as an evaluation parameter
# ---------------------------------------------------------------------------

DISTS = {
    ("U1", "S1"): 150,
    ("U2", "S1"): 200,
    ("S1", "B1"): 800,
    ("S1", "B2"): 850,
    ("B1", "SAT1"): 1000,
    ("B2", "SAT2"): 1000,
    ("SAT1", "BS"): 500,
    ("SAT2", "BS"): 500,
}

NODES = {
    "UWS": ["U1", "U2"],
    "SUB": ["S1"],
    "BUOY": ["B1", "B2"],
    "SAT": ["SAT1", "SAT2"],
    "BS": ["BS"],
}

EDGES = [
    ("U1", "S1"), ("U2", "S1"),
    ("S1", "B1"), ("S1", "B2"),
    ("B1", "SAT1"), ("B1", "SAT2"),
    ("B2", "SAT1"), ("B2", "SAT2"),
    ("SAT1", "BS"), ("SAT2", "BS"),
]

# Direct registration links used to build the registration set (RID chain).
DIRECT_LINKS = [
    ("U1", "S1"), ("U2", "S1"),
    ("S1", "B1"), ("S1", "B2"),
    ("B1", "SAT1"), ("B1", "SAT2"),
    ("B2", "SAT1"), ("B2", "SAT2"),
    ("SAT1", "BS"), ("SAT2", "BS"),
]

# Static peer adjacency used for path/fallback selection.
PEERS = {
    "U1": ["S1"], "U2": ["S1"],
    "S1": ["U1", "U2", "B1", "B2"],
    "B1": ["S1", "SAT1", "SAT2"],
    "B2": ["S1", "SAT1", "SAT2"],
    "SAT1": ["B1", "B2", "BS"],
    "SAT2": ["B1", "B2", "BS"],
    "BS": ["SAT1", "SAT2"],
}

# ---------------------------------------------------------------------------
# NSL-style message tags, one triple per hop (a: initiator->responder,
# b: responder->initiator, c: initiator->responder)
# ---------------------------------------------------------------------------

TAGS = {
    1: ("h1a", "h1b", "h1c"),
    2: ("h2a", "h2b", "h2c"),
    3: ("h3a", "h3b", "h3c"),
    4: ("h4a", "h4b", "h4c"),
}

# ---------------------------------------------------------------------------
# Reference/comparison numbers from prior related schemes, retained for
# reproducibility. These should be independently checked against the source
# papers before any academic use.
# ---------------------------------------------------------------------------

COMPARISON = {
    "Ref [21]": {"comm": 3008, "uws": 0.536, "sub": 0.800},
    "Ref [22]": {"comm": 3200, "uws": 19.70, "sub": 25.00},
    "Ref [23]": {"comm": 3136, "uws": 75.88, "sub": 90.00},
    "Ref [24]": {"comm": 3040, "uws": 2.352, "sub": 2.900},
    "Ref [25]": {"comm": 3216, "uws": 1.245, "sub": 1.600},
    "Proposed": {"comm": 2112, "uws": 0.400, "sub": 0.500},
}
