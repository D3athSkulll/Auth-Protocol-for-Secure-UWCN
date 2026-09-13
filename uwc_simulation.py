"""
PEECC / UWC Authentication + Evaluation Simulation
===================================================

Single-file runner built from the clean PEECC/UWCN architecture (Code 1)
with the evaluation, plots, and measurements used by the earlier improved
simulation (Code 2).

PROTOCOL SOURCE OF TRUTH
------------------------
The security/protocol core follows the supplied Scyther model:

    UWS <-> SUB <-> BUOY <-> SAT <-> BS

Each hop is an independent 3-message NSL-style exchange:

    M1/M2/M3  = UWS  <-> SUB
    M4/M5/M6  = SUB  <-> BUOY
    M7/M8/M9  = BUOY <-> SAT
    M10/M11/M12 = SAT <-> BS

Within each hop:
    a) initiator -> responder: {tag_a, initiator_ID, fresh_nonce}pk(responder)
    b) responder -> initiator: {tag_b, nonce_i, fresh_nonce_r, responder_ID}pk(initiator)
    c) initiator -> responder: {tag_c, nonce_r}pk(responder)

IMPORTANT
---------
This file is intentionally kept as a runnable protocol/evaluation model,
not a production cryptographic implementation. The paper gives a PEECC
5-dimensional representation but does not provide a complete executable
5-D group law and public-key-encryption construction. The PEECC backend here
is therefore an isolated symbolic/simulation abstraction. Do not interpret
its XOR envelope as deployable security.

The added Code-2-style features are evaluation models around the protocol:
  - AES-GCM timing benchmark (does NOT replace protocol crypto)
  - Thorp-based acoustic delay model
  - packet loss + retransmission model
  - per-node energy/battery accounting
  - UWS/SUB mobility
  - delay anomaly detection
  - scaling experiment
  - comparison plots
  - throughput estimate
  - seven PNG output graphs

Run:
    python uwc_simulation.py

Outputs:
    output_topology.png
    output_delay.png
    output_energy.png
    output_comm_cost.png
    output_comparison.png
    output_throughput.png
    output_battery.png
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
import random
import statistics
import time
from typing import Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None


# ============================================================================
# Configuration
# ============================================================================

HASH_NAME = "sha256"
P = 2**255 - 19
D = 2
GENERATOR = (5, 7, 11, 13, 17)
TSW = 5.0

# Code 2 evaluation settings.
SOUND_MPS = 1500.0
ACOUSTIC_FREQ_KHZ = 25.0
LOSS_RATE = 0.15
MAX_RETRY = 3
BAT_uJ = 3_300_000.0
AUTH_uJ = 48.8
TX_uJ = 50.0
RX_uJ = 36.0
SCALE_SIZES = [10, 20, 50, 100, 150, 200]
ANOMALY_THRESHOLD = 2.5

# Physical distances retained from Code 2, as an evaluation parameter.
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

TAGS = {
    1: ("h1a", "h1b", "h1c"),
    2: ("h2a", "h2b", "h2c"),
    3: ("h3a", "h3b", "h3c"),
    4: ("h4a", "h4b", "h4c"),
}

# Prior Code-2 comparison numbers retained for reproducibility.
# They should be independently checked against the paper before academic use.
COMPARISON = {
    "Ref [21]": {"comm": 3008, "uws": 0.536, "sub": 0.800},
    "Ref [22]": {"comm": 3200, "uws": 19.70, "sub": 25.00},
    "Ref [23]": {"comm": 3136, "uws": 75.88, "sub": 90.00},
    "Ref [24]": {"comm": 3040, "uws": 2.352, "sub": 2.900},
    "Ref [25]": {"comm": 3216, "uws": 1.245, "sub": 1.600},
    "Proposed": {"comm": 2112, "uws": 0.400, "sub": 0.500},
}


# ============================================================================
# Utility functions
# ============================================================================

def h(*parts: object) -> str:
    material = "|".join(str(x) for x in parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def canonical_point(point: "PEECCPoint") -> str:
    return ",".join(str(v) for v in point.coords)


def random_scalar() -> int:
    return int.from_bytes(os.urandom(32), "big") % P or 1


def new_nonce() -> int:
    return int.from_bytes(os.urandom(8), "big")


def xor_stream(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ============================================================================
# PEECC simulation backend -- same architecture as Code 1
# ============================================================================

@dataclass(frozen=True)
class PEECCPoint:
    coords: Tuple[int, int, int, int, int]

    def __post_init__(self) -> None:
        if len(self.coords) != 5:
            raise ValueError("PEECC point must contain five coordinates")

    def scalar_mul(self, k: int) -> "PEECCPoint":
        return PEECCPoint(tuple((k * x) % P for x in self.coords))


class PEECCBackend:
    def __init__(self, prime: int = P, d: int = D) -> None:
        self.p = prime
        self.d = d
        self.generator = PEECCPoint(tuple(x % prime for x in GENERATOR))

    def generate_keypair(self) -> Tuple[int, PEECCPoint]:
        private = random_scalar()
        return private, self.generator.scalar_mul(private)

    def shared_point(self, private: int, peer_public: PEECCPoint) -> PEECCPoint:
        return peer_public.scalar_mul(private)

    def derive_key(self, point: PEECCPoint) -> bytes:
        return hashlib.sha256(canonical_point(point).encode()).digest()

    def encrypt(self, sender_private: int, receiver_public: PEECCPoint,
                plaintext: str) -> bytes:
        point = self.shared_point(sender_private, receiver_public)
        return xor_stream(plaintext.encode(), self.derive_key(point))

    def decrypt(self, receiver_private: int, sender_public: PEECCPoint,
                ciphertext: bytes) -> str:
        point = self.shared_point(receiver_private, sender_public)
        return xor_stream(ciphertext, self.derive_key(point)).decode()


@dataclass
class Entity:
    name: str
    role: str
    private_key: int
    public_key: PEECCPoint
    identifier: str
    peers: List[str] = field(default_factory=list)
    registered: Dict[str, str] = field(default_factory=dict)


# ============================================================================
# Protocol + simulation
# ============================================================================

class UWCSimulation:
    def __init__(self) -> None:
        self.crypto = PEECCBackend()
        self.entities: Dict[str, Entity] = {}
        self.registration_set: set[str] = set()
        self.sessions: Dict[Tuple[str, str], str] = {}

        # Code-2-style evaluation state.
        self.battery = {name: BAT_uJ for names in NODES.values() for name in names}
        self.mobility = {name: 0.0 for names in NODES.values() for name in names}
        self.delay_log: List[float] = []
        self.hop_delay_log: List[Tuple[int, str, str, float]] = []
        self.packet_stats = {"attempts": 0, "lost": 0, "retries": 0,
                             "delivered": 0, "failed": 0}
        self.message_records: List[Dict[str, object]] = []
        self.round_results: List[bool] = []
        self.clean_result: Optional[bool] = None
        self.data_payload: Dict[str, object] = {}

        self._initialize_system()

    # ---------------------------------------------------------------------
    # Initialization / registration
    # ---------------------------------------------------------------------

    def _initialize_system(self) -> None:
        print("\n=== SYSTEM INITIALISATION ===")
        for role, names in NODES.items():
            for name in names:
                private, public = self.crypto.generate_keypair()
                identifier = h(canonical_point(public), name)
                self.entities[name] = Entity(name, role, private, public, identifier)

        peers = {
            "U1": ["S1"], "U2": ["S1"],
            "S1": ["U1", "U2", "B1", "B2"],
            "B1": ["S1", "SAT1", "SAT2"],
            "B2": ["S1", "SAT1", "SAT2"],
            "SAT1": ["B1", "B2", "BS"],
            "SAT2": ["B1", "B2", "BS"],
            "BS": ["SAT1", "SAT2"],
        }
        for name, plist in peers.items():
            self.entities[name].peers = plist

        for e in self.entities.values():
            print(f"{e.name:5s} role={e.role:5s} ID={e.identifier[:20]}...")

    def register_entity(self, name: str) -> None:
        e = self.entities[name]
        rid = h(e.identifier, canonical_point(e.public_key), e.private_key)
        theta = h(rid, canonical_point(e.public_key))
        e.registered["RID"] = rid
        e.registered["THETA"] = theta
        self.registration_set.add(rid)
        print(f"[REGISTERED] {name:5s} RID={rid[:16]}...")

    def register_network(self) -> None:
        print("\n=== REGISTRATION PHASE ===")
        for name in self.entities:
            self.register_entity(name)

        direct_links = [
            ("U1", "S1"), ("U2", "S1"),
            ("S1", "B1"), ("S1", "B2"),
            ("B1", "SAT1"), ("B1", "SAT2"),
            ("B2", "SAT1"), ("B2", "SAT2"),
            ("SAT1", "BS"), ("SAT2", "BS"),
        ]
        for a, b in direct_links:
            self._register_link(a, b)
        print(f"Registration set R: {len(self.registration_set)} unique RIDs")

    def _register_link(self, a: str, b: str) -> bool:
        ea, eb = self.entities[a], self.entities[b]
        theta = h(ea.registered["RID"], canonical_point(ea.public_key))
        if theta != ea.registered["THETA"]:
            return False
        eb.registered[a] = ea.registered["RID"]
        eb.registered[a + ":THETA"] = theta
        return True

    # ---------------------------------------------------------------------
    # Code-2 acoustic / mobility / energy models
    # ---------------------------------------------------------------------

    @staticmethod
    def thorp_db_per_km(freq_khz: float) -> float:
        f2 = freq_khz ** 2
        return (0.11 * f2 / (1 + f2)
                + 44 * f2 / (4100 + f2)
                + 2.75e-4 * f2 + 0.003)

    def update_mobility(self) -> None:
        for node in ("U1", "U2", "S1"):
            self.mobility[node] += random.uniform(-10.0, 10.0)
            self.mobility[node] = max(-50.0, min(50.0, self.mobility[node]))

    def acoustic_delay(self, sender: str, receiver: str) -> float:
        key = (sender, receiver) if (sender, receiver) in DISTS else (receiver, sender)
        distance = DISTS.get(key, 500) + abs(self.mobility.get(sender, 0.0))
        distance = max(10.0, distance)
        propagation = distance / SOUND_MPS
        absorption = self.thorp_db_per_km(ACOUSTIC_FREQ_KHZ) * (distance / 1000) * 1e-4
        multipath = abs(random.gauss(0, 0.005))
        return propagation + absorption + multipath

    def use_energy(self, node: str, operation: str) -> None:
        amount = {"auth": AUTH_uJ, "tx": TX_uJ, "rx": RX_uJ}[operation]
        self.battery[node] -= amount

    # ---------------------------------------------------------------------
    # Message primitives
    # ---------------------------------------------------------------------

    def _encrypt_fields(self, sender: str, receiver: str, fields: List[str]) -> bytes:
        return self.crypto.encrypt(
            self.entities[sender].private_key,
            self.entities[receiver].public_key,
            "|".join(fields),
        )

    def _decrypt_fields(self, sender: str, receiver: str, ciphertext: bytes) -> List[str]:
        plaintext = self.crypto.decrypt(
            self.entities[receiver].private_key,
            self.entities[sender].public_key,
            ciphertext,
        )
        return plaintext.split("|")

    def _send_message(self, message_name: str, msg_no: int,
                      sender: str, receiver: str, fields: List[str],
                      retries_enabled: bool = True) -> Optional[List[str]]:
        """Send one protocol message, applying Code-2 channel loss model."""
        attempts = 0
        while attempts < (MAX_RETRY if retries_enabled else 1):
            attempts += 1
            self.packet_stats["attempts"] += 1
            delay = self.acoustic_delay(sender, receiver)
            self.delay_log.append(delay)
            self.hop_delay_log.append((msg_no, sender, receiver, delay))

            if random.random() < LOSS_RATE:
                self.packet_stats["lost"] += 1
                if attempts < MAX_RETRY:
                    self.packet_stats["retries"] += 1
                    continue
                self.packet_stats["failed"] += 1
                return None

            self.use_energy(sender, "tx")
            self.use_energy(receiver, "rx")
            cipher = self._encrypt_fields(sender, receiver, fields)
            decoded = self._decrypt_fields(sender, receiver, cipher)
            self.packet_stats["delivered"] += 1
            self.message_records.append({
                "message": message_name,
                "number": msg_no,
                "sender": sender,
                "receiver": receiver,
                "fields": fields,
                "ciphertext_bytes": len(cipher),
                "delay_s": delay,
            })
            return decoded
        return None

    def _check_timestamp(self, t_sent: float, t_recv: float) -> bool:
        return abs(t_recv - t_sent) < TSW

    def _new_session(self, a: str, b: str) -> str:
        sid = h("SESSION", a, b, new_nonce())
        self.sessions[(a, b)] = sid
        self.sessions[(b, a)] = sid
        return sid

    # ---------------------------------------------------------------------
    # One exact NSL hop -- mirrors the Scyther file
    # ---------------------------------------------------------------------

    def authenticate_hop(self, hop: int, initiator: str, responder: str,
                         labels: Tuple[str, str, str],
                         message_numbers: Tuple[int, int, int],
                         message_names: Tuple[str, str, str]) -> bool:
        taga, tagb, tagc = labels
        m1, m2, m3 = message_numbers
        n1 = new_nonce()
        sent_ts = time.time()

        # M(a): {tag_a, initiator, Ni}pk(responder)
        decoded1 = self._send_message(
            message_names[0], m1, initiator, responder,
            [taga, initiator, str(n1)],
        )
        if decoded1 is None:
            return False
        if decoded1 != [taga, initiator, str(n1)]:
            return False

        # Responder generates Nr and returns {tag_b, Ni, Nr, responder}.
        nr = new_nonce()
        responder_ts = time.time()
        decoded2 = self._send_message(
            message_names[1], m2, responder, initiator,
            [tagb, str(n1), str(nr), responder],
        )
        if decoded2 is None:
            return False
        if decoded2 != [tagb, str(n1), str(nr), responder]:
            return False

        if not self._check_timestamp(sent_ts, responder_ts):
            return False

        # M(c): {tag_c, Nr}pk(responder)
        decoded3 = self._send_message(
            message_names[2], m3, initiator, responder,
            [tagc, str(nr)],
        )
        if decoded3 is None:
            return False
        if decoded3 != [tagc, str(nr)]:
            return False

        self._new_session(initiator, responder)
        self.use_energy(initiator, "auth")
        self.use_energy(responder, "auth")
        print(f"[AUTH OK] {initiator} <-> {responder}  "
              f"Ni={str(n1)[:10]}... Nr={str(nr)[:10]}...")
        return True

    # ---------------------------------------------------------------------
    # Exact 12-message authentication sequence
    # ---------------------------------------------------------------------

    def run_ns_authentication(self, buoy: str = "B1", satellite: str = "SAT1") -> bool:
        print("\n=== M1-M12 NSL AUTHENTICATION ===")
        print(f"Path: U1 -> S1 -> {buoy} -> {satellite} -> BS")

        self.update_mobility()

        hops = [
            (1, "U1", "S1", TAGS[1], (1, 2, 3), ("M1", "M2", "M3")),
            (2, "S1", buoy, TAGS[2], (4, 5, 6), ("M4", "M5", "M6")),
            (3, buoy, satellite, TAGS[3], (7, 8, 9), ("M7", "M8", "M9")),
            (4, satellite, "BS", TAGS[4], (10, 11, 12), ("M10", "M11", "M12")),
        ]

        for hop, a, b, tags, nums, names in hops:
            ok = self.authenticate_hop(hop, a, b, tags, nums, names)
            print(f"Hop {hop}: {a} <-> {b}: {'SUCCESS' if ok else 'FAILED'}")
            if not ok:
                return False
        print("=== ALL M1-M12 MESSAGES SUCCESSFUL ===")
        return True

    # ---------------------------------------------------------------------
    # Data flow is kept separate from Scyther's M1-M12 authentication.
    # This avoids the earlier mismatch where M3/M6/M9/M12 were simultaneously
    # treated as NSL messages and sensor/data packets.
    # ---------------------------------------------------------------------

    def run_data_flow(self, buoy: str = "B1", satellite: str = "SAT1") -> bool:
        print("\n=== SENSOR / ENVIRONMENT DATA FLOW ===")
        sensor = {
            "Temp": round(random.uniform(10, 30), 2),
            "Pressure": round(random.uniform(1, 5), 2),
            "Velocity": round(random.uniform(0, 3), 2),
            "Salinity": round(random.uniform(30, 40), 2),
        }
        gps = {"lat": 17.3850, "lon": 78.4867}
        alerts = ["jamming", "spoofing", "eavesdropping"]
        logs = "mission=UWC-DEMO,status=nominal,events=0"

        print(f"UWS sensor data: {sensor}")
        print(f"SUB receives ENV and forwards it to {buoy}")
        print(f"BUOY adds GPS={gps} and forwards to {satellite}")
        print(f"SAT adds LOGS and forwards the complete package to BS")

        self.data_payload = {
            "ENV": sensor,
            "ALERTS": alerts,
            "GPS": gps,
            "LOGS": logs,
        }
        return True

    # ---------------------------------------------------------------------
    # Code-2 evaluation features
    # ---------------------------------------------------------------------

    def replay_test(self) -> None:
        print("\n=== REPLAY / FRESHNESS TEST ===")
        old_ts = time.time() - (TSW + 1.0)
        accepted = self._check_timestamp(old_ts, time.time())
        print("Replay ACCEPTED (BUG)" if accepted else "Replay blocked")

    def detect_anomalies(self, threshold: float = ANOMALY_THRESHOLD) -> List[int]:
        if len(self.delay_log) < 4:
            return []
        mean = statistics.mean(self.delay_log)
        stdev = statistics.stdev(self.delay_log)
        if stdev == 0:
            return []
        return [i for i, delay in enumerate(self.delay_log)
                if abs((delay - mean) / stdev) > threshold]

    def run_rounds_with_fallback(self, rounds: int = 5) -> None:
        print("\n=== REPEATED EXPERIMENT: 5 ROUNDS + FALLBACK ===")
        for i in range(1, rounds + 1):
            print(f"\n[Round {i}]")
            # Model the Code-2 fallback scenario, but do not alter the NSL core.
            unavailable_b = {"B1"} if i % 2 == 1 else set()
            unavailable_s = {"SAT1"} if i % 3 == 0 else set()
            buoy = self.choose_peer("S1", ["B1", "B2"], unavailable_b)
            if buoy is None:
                self.round_results.append(False)
                print("No registered BUOY available")
                continue
            sat = self.choose_peer(buoy, ["SAT1", "SAT2"], unavailable_s)
            if sat is None:
                self.round_results.append(False)
                print("No registered SAT available")
                continue

            ok = self.run_ns_authentication(buoy=buoy, satellite=sat)
            self.round_results.append(ok)
            print(f"Result: {'SUCCESS' if ok else 'FAILED'}")

    def choose_peer(self, current: str, candidates: List[str],
                    unavailable: Optional[set[str]] = None) -> Optional[str]:
        unavailable = unavailable or set()
        for candidate in candidates:
            if candidate in self.entities[current].peers and candidate not in unavailable:
                return candidate
        return None

    def communication_bits(self) -> int:
        # Code-2 reference retained for comparison, plus actual ciphertext
        # sizes observed in this M1-M12 run.
        actual = sum(int(r["ciphertext_bytes"]) * 8 for r in self.message_records)
        reference = 296
        return actual if actual else reference

    def energy_summary(self) -> Dict[str, float]:
        used = {n: BAT_uJ - value for n, value in self.battery.items()}
        return used

    def aes_gcm_benchmark(self) -> Optional[float]:
        if AESGCM is None:
            return None
        key = AESGCM.generate_key(bit_length=256)
        aes = AESGCM(key)
        nonce = os.urandom(12)
        payload = b"UWC-AES-GCM-BENCHMARK"
        t0 = time.perf_counter()
        ct = aes.encrypt(nonce, payload, None)
        aes.decrypt(nonce, ct, None)
        return time.perf_counter() - t0

    # ---------------------------------------------------------------------
    # Scaling model and output figures -- same family as Code 2
    # ---------------------------------------------------------------------

    def scaling_data(self, sizes: List[int]) -> Tuple[List[int], List[float], List[float], List[float], List[float]]:
        delays, energies, comms, throughput = [], [], [], []
        base_path = [("U1", "S1"), ("S1", "B2"), ("B2", "SAT2"), ("SAT2", "BS")]
        for n in sizes:
            path_delays = []
            for _ in range(max(1, n // 8)):
                path_delays.append(sum(self._scale_delay(a, b) for a, b in base_path))
            mean_delay = statistics.mean(path_delays)
            delays.append(mean_delay)
            energies.append(AUTH_uJ + n * 0.1)
            comms.append(296 + n * 10)
            throughput.append(1.0 / mean_delay if mean_delay else 0.0)
        return sizes, delays, energies, comms, throughput

    def _scale_delay(self, sender: str, receiver: str) -> float:
        key = (sender, receiver) if (sender, receiver) in DISTS else (receiver, sender)
        distance = max(10.0, DISTS.get(key, 500) + random.uniform(-20, 20))
        prop = distance / SOUND_MPS
        absorption = self.thorp_db_per_km(ACOUSTIC_FREQ_KHZ) * distance / 1000 * 1e-4
        multipath = abs(random.gauss(0, 0.005))
        return prop + absorption + multipath

    @staticmethod
    def save_fig(fig, filename: str) -> None:
        fig.tight_layout()
        fig.savefig(filename, dpi=150, bbox_inches="tight")
        plt.close(fig)
        print(f"Saved: {filename}")

    def generate_graphs(self) -> None:
        ns, delays, energies, comms, throughput = self.scaling_data(SCALE_SIZES)

        # Graph 1: topology
        graph = nx.Graph()
        graph.add_edges_from(EDGES)
        colors = {
            "U1": "#3498db", "U2": "#3498db", "S1": "#2ecc71",
            "B1": "#e67e22", "B2": "#2ecc71",
            "SAT1": "#9b59b6", "SAT2": "#9b59b6", "BS": "#f39c12",
        }
        pos = {
            "U1": (0.35, 1.0), "U2": (0.65, 1.0), "S1": (0.5, 0.72),
            "B1": (0.2, 0.44), "B2": (0.8, 0.44),
            "SAT1": (0.2, 0.16), "SAT2": (0.8, 0.16), "BS": (0.5, -0.1),
        }
        fig, ax = plt.subplots(figsize=(10, 7))
        nx.draw_networkx(graph, pos, ax=ax,
                         node_color=[colors[n] for n in graph.nodes()],
                         node_size=1100, font_size=10, font_weight="bold",
                         edge_color="#7f8c8d", width=2, with_labels=True)
        active = [("U1", "S1"), ("S1", "B2"), ("B2", "SAT2"), ("SAT2", "BS")]
        nx.draw_networkx_edges(graph, pos, edgelist=active, ax=ax,
                               edge_color="#27ae60", width=3.5)
        ax.set_title("PEECC-UWCN Topology | M1-M12 Active Path\n"
                     "Code-2 evaluation layer may fall back between registered peers")
        ax.legend(handles=[
            mpatches.Patch(color="#3498db", label="UWS"),
            mpatches.Patch(color="#2ecc71", label="SUB / active relay"),
            mpatches.Patch(color="#e67e22", label="BUOY"),
            mpatches.Patch(color="#9b59b6", label="SAT"),
            mpatches.Patch(color="#f39c12", label="BS"),
        ], loc="upper left", fontsize=8)
        self.save_fig(fig, "output_topology.png")

        # Graph 2: delay
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(ns, delays, marker="o", lw=2, label="M1-M12 path delay")
        ax.axhline(0.211, ls="--", lw=1.5, label="Code-2 reference 211 ms")
        ax.set_title("Authentication Path Delay vs Number of Nodes")
        ax.set_xlabel("Number of Nodes")
        ax.set_ylabel("Mean Delay (s)")
        ax.legend()
        ax.grid(alpha=0.4)
        self.save_fig(fig, "output_delay.png")

        # Graph 3: energy
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(ns, energies, marker="o", lw=2, label="Evaluation energy model")
        ax.axhline(280, ls="--", lw=1.5, label="Ref [24] reference")
        ax.axhline(2300, ls=":", lw=1.5, label="Ref [22] reference")
        ax.set_title("Energy Consumption vs Number of Nodes")
        ax.set_xlabel("Number of Nodes")
        ax.set_ylabel("Energy per Auth Cycle (uJ)")
        ax.legend()
        ax.grid(alpha=0.4)
        self.save_fig(fig, "output_energy.png")

        # Graph 4: communication cost
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(ns, comms, marker="o", lw=2, label="Evaluation estimate")
        for ref in ("Ref [21]", "Ref [22]", "Ref [23]"):
            ax.plot(ns, [COMPARISON[ref]["comm"] + n * 10 for n in ns], "--",
                    lw=1.1, label=ref)
        ax.set_title("Communication Cost vs Number of Nodes")
        ax.set_xlabel("Number of Nodes")
        ax.set_ylabel("Bits")
        ax.legend(fontsize=8)
        ax.grid(alpha=0.4)
        self.save_fig(fig, "output_comm_cost.png")

        # Graph 5: comparison
        schemes = list(COMPARISON)
        x = list(range(len(schemes)))
        width = 0.35
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        axes[0].bar([v - width / 2 for v in x],
                    [COMPARISON[s]["uws"] for s in schemes], width,
                    label="UWS/BS")
        axes[0].bar([v + width / 2 for v in x],
                    [COMPARISON[s]["sub"] for s in schemes], width,
                    label="SUB/SAT", alpha=0.55)
        axes[0].set_yscale("log")
        axes[0].set_xticks(x)
        axes[0].set_xticklabels(schemes, rotation=20)
        axes[0].set_ylabel("Time (ms)")
        axes[0].set_title("Computational Cost")
        axes[0].legend(fontsize=8)
        axes[1].bar(schemes, [COMPARISON[s]["comm"] for s in schemes])
        axes[1].set_ylabel("Bits")
        axes[1].set_title("Communication Overhead")
        axes[1].tick_params(axis="x", rotation=20)
        self.save_fig(fig, "output_comparison.png")

        # Graph 6: throughput
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(ns, throughput, marker="s", lw=2, label="1 / mean path delay")
        ax.set_title("Authentication Throughput vs Network Scale")
        ax.set_xlabel("Number of Nodes")
        ax.set_ylabel("Authentications per Second")
        ax.legend()
        ax.grid(alpha=0.4)
        self.save_fig(fig, "output_throughput.png")

        # Graph 7: battery
        labels = list(self.battery)
        percentages = [100 * self.battery[n] / BAT_uJ for n in labels]
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
        self.save_fig(fig, "output_battery.png")

    # ---------------------------------------------------------------------
    # Final report
    # ---------------------------------------------------------------------

    def print_report(self) -> None:
        anomalies = self.detect_anomalies()
        aes_time = self.aes_gcm_benchmark()
        used = self.energy_summary()
        comm_bits = self.communication_bits()

        print("\n=== RUN SUMMARY ===")
        overall = self.clean_result if self.clean_result is not None else False
        print(f"M1-M12 clean authentication: {'SUCCESS' if overall else 'FAILED'}")
        if self.round_results:
            print(f"Evaluation rounds       : {sum(self.round_results)}/{len(self.round_results)} successful")
        print(f"Messages attempted     : {self.packet_stats['attempts']}")
        print(f"Messages delivered     : {self.packet_stats['delivered']}")
        print(f"Packets lost           : {self.packet_stats['lost']}")
        print(f"Retransmissions        : {self.packet_stats['retries']}")
        print(f"Link failures          : {self.packet_stats['failed']}")
        print(f"Mean acoustic delay    : {statistics.mean(self.delay_log) if self.delay_log else 0:.6f} s")
        print(f"Max acoustic delay     : {max(self.delay_log) if self.delay_log else 0:.6f} s")
        print(f"Communication estimate : {comm_bits} bits (observed encrypted payloads)")
        print(f"Code-2 reference       : 296 bits/message")
        print(f"Anomalous delay hops   : {anomalies if anomalies else 'none'}")
        if aes_time is None:
            print("AES-GCM benchmark      : unavailable (install cryptography)")
        else:
            print(f"AES-GCM benchmark      : {aes_time:.8f} s [benchmark only]")

        print("\nEnergy consumed per node:")
        for node, amount in used.items():
            print(f"  {node:5s}: {amount:.2f} uJ  | remaining={100*self.battery[node]/BAT_uJ:.4f}%")

        print("\nSensor payload delivered logically to BS:")
        print(self.data_payload)


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    print("=" * 78)
    print(" PEECC / UWC AUTHENTICATION + CODE-2 EVALUATION SINGLE-FILE RUNNER")
    print("=" * 78)

    sim = UWCSimulation()
    sim.register_network()

    # First: one clean deterministic protocol run.
    clean = sim.run_ns_authentication("B1", "SAT1")
    sim.clean_result = clean
    print(f"\nClean M1-M12 run: {'SUCCESS' if clean else 'FAILED'}")

    # Data is separate from the NSL messages, matching the Scyther model.
    sim.run_data_flow("B1", "SAT1")

    # Code-2-style evaluation tests.
    sim.replay_test()
    sim.run_rounds_with_fallback(rounds=5)

    sim.generate_graphs()
    sim.print_report()

    print("\n=== OUTPUT FILES ===")
    for filename in (
        "output_topology.png", "output_delay.png", "output_energy.png",
        "output_comm_cost.png", "output_comparison.png",
        "output_throughput.png", "output_battery.png",
    ):
        print(f"  {filename}")

    print("\nScyther mapping:")
    print("  Hop 1: M1/M2/M3   = uwchop1(UWS,SUB)")
    print("  Hop 2: M4/M5/M6   = uwchop2(SUB,BUOY)")
    print("  Hop 3: M7/M8/M9   = uwchop3(BUOY,SAT)")
    print("  Hop 4: M10/M11/M12 = uwchop4(SAT,BS)")
    print("\nUse the supplied uwc_protocol.spdl with Scyther for formal verification.")
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
