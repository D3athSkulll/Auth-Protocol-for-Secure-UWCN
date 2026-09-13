"""
PEECC / UWC Base Implementation
--------------------------------

Baseline implementation of the architecture proposed in:

C. Rupa et al., "A Novel and Robust Authentication Protocol for
Secure Underwater Communication Systems," IEEE Internet of Things
Journal, vol. 12, no. 22, pp. 47519-47531, 2025.

This is the FIRST / BASE COMMIT.

Implemented from the paper:
  1. System initialization
  2. Registration
  3. Hop-wise mutual authentication
  4. UWS -> SUB -> BUOY -> SAT -> BS data flow
  5. Messages M1-M12
  6. Nonce + timestamp checks
  7. Registration identifier RID and verification value theta
  8. Alternate peers for the paper's fallback architecture

Intentionally NOT included in this base commit:
  - AES-GCM
  - Thorp acoustic absorption
  - packet-loss / retransmission model
  - battery accounting
  - node mobility model
  - delay anomaly detection
  - prior-scheme comparison plots
  - throughput/scaling experiments
  - forced node failures
  - standard secp256r1 ECC

IMPORTANT CRYPTOGRAPHIC NOTE
----------------------------
The paper specifies the pentatope representation and the protocol notation,
but does not provide a complete, executable 5-D group law or a complete
public-key encryption construction. Therefore the PEECCBackend below is an
explicit *protocol simulation abstraction*:

    public = private * generator
    shared  = private_A * public_B = private_B * public_A

The multiplication is represented coordinate-wise modulo p. This lets the
protocol implementation follow the paper's data flow without silently
substituting secp256r1 or claiming that this is a production PEECC library.

The message envelope uses a deterministic XOR stream derived from the shared
PEECC point. This mirrors the lightweight "encrypt/decrypt" abstraction used
by the original simulation while keeping the cryptographic layer isolated so
a real PEECC implementation can replace it in a later commit.

No claim is made that this XOR construction is secure for deployment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
import time
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Global protocol parameters
# ---------------------------------------------------------------------------

HASH_NAME = "sha256"

# A large prime used for the software model.
# It is a simulation parameter, not a curve parameter copied from the paper.
P = 2**255 - 19

# The paper uses a pentatope curve:
#
#   psi = X^3 + Y^3 + Z^3 + W^3 + T^3 = dXYZWT
#
# We retain d as an explicit system parameter.
D = 2

# The paper uses a generator point rho = (Xrho, Yrho, Zrho, Wrho, Trho)
# with a large prime order n.
GENERATOR = (5, 7, 11, 13, 17)

# Timestamp tolerance.
#
# The paper discusses an adaptive timestamp window, but does not specify a
# concrete update equation.  The base implementation therefore uses a fixed
# simulation value and keeps the timestamp logic local to each hop.
DELTA_T = 5.0


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def h(*parts: object) -> str:
    """SHA-256 over a deterministic textual concatenation."""
    material = "|".join(str(part) for part in parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def canonical_point(point: "PEECCPoint") -> str:
    return ",".join(str(v) for v in point.coords)


def random_scalar() -> int:
    return int.from_bytes(os.urandom(32), "big") % P or 1


def new_nonce() -> int:
    return int.from_bytes(os.urandom(8), "big")


# ---------------------------------------------------------------------------
# PEECC abstraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PEECCPoint:
    """
    Five-dimensional point representation used by the protocol model.

    The paper defines a 5-D pentatope point group, but does not give a
    complete implementable group operation.  Scalar multiplication is
    therefore represented coordinate-wise modulo P in this baseline.
    """

    coords: Tuple[int, int, int, int, int]

    def __post_init__(self) -> None:
        if len(self.coords) != 5:
            raise ValueError("PEECC points must have exactly 5 coordinates")

    def scalar_mul(self, k: int) -> "PEECCPoint":
        return PEECCPoint(tuple((k * x) % P for x in self.coords))


class PEECCBackend:
    """Small isolated cryptographic backend for the protocol simulation."""

    def __init__(self, prime: int = P, d: int = D) -> None:
        self.p = prime
        self.d = d
        self.generator = PEECCPoint(tuple(x % prime for x in GENERATOR))

    def generate_keypair(self) -> Tuple[int, PEECCPoint]:
        private = random_scalar()
        public = self.generator.scalar_mul(private)
        return private, public

    def shared_point(self, private: int, peer_public: PEECCPoint) -> PEECCPoint:
        return peer_public.scalar_mul(private)

    def derive_key(self, shared_point: PEECCPoint) -> bytes:
        return hashlib.sha256(
            canonical_point(shared_point).encode("utf-8")
        ).digest()

    def encrypt(
        self,
        sender_private: int,
        receiver_public: PEECCPoint,
        plaintext: str,
    ) -> bytes:
        """
        Reference envelope:

            K = H(PK_sender * PU_receiver)
            C = plaintext XOR K-stream

        Receiver reconstructs the same point using its private key and the
        sender's public key.
        """
        shared = self.shared_point(sender_private, receiver_public)
        key = self.derive_key(shared)
        data = plaintext.encode("utf-8")
        return xor_stream(data, key)

    def decrypt(
        self,
        receiver_private: int,
        sender_public: PEECCPoint,
        ciphertext: bytes,
    ) -> str:
        shared = self.shared_point(receiver_private, sender_public)
        key = self.derive_key(shared)
        data = xor_stream(ciphertext, key)
        return data.decode("utf-8")


def xor_stream(data: bytes, key: bytes) -> bytes:
    """Repeat the derived key as a simple simulation stream."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ---------------------------------------------------------------------------
# Entity model
# ---------------------------------------------------------------------------

@dataclass
class Entity:
    name: str
    role: str
    private_key: int
    public_key: PEECCPoint
    identifier: str

    # Registered peers known to this entity.
    registered: Dict[str, str] = field(default_factory=dict)

    # The paper describes local trusted peer caches for fallback operation.
    peers: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# System initialization
# ---------------------------------------------------------------------------

class UWCNProtocol:
    """
    Implements the paper's five logical entity classes:

        UWS -> SUB -> B -> SAT -> BS

    The concrete simulation contains two UWS nodes, one SUB, two buoys,
    two satellites, and one base station.
    """

    def __init__(self) -> None:
        self.crypto = PEECCBackend()

        self.roles = {
            "UWS": ["U1", "U2"],
            "SUB": ["S1"],
            "BUOY": ["B1", "B2"],
            "SAT": ["SAT1", "SAT2"],
            "BS": ["BS"],
        }

        self.entities: Dict[str, Entity] = {}
        self.registration_set: set[str] = set()
        self.sessions: Dict[Tuple[str, str], str] = {}

        self._initialize_system()

    def _initialize_system(self) -> None:
        print("\n=== SYSTEM INITIALIZATION ===")

        for role, names in self.roles.items():
            for name in names:
                private, public = self.crypto.generate_keypair()

                # Paper: ID_i = H(PU_i || E)
                identifier = h(canonical_point(public), name)

                self.entities[name] = Entity(
                    name=name,
                    role=role,
                    private_key=private,
                    public_key=public,
                identifier=identifier,
                )

        # Logical neighbor/cache structure from the hierarchical topology.
        self._set_peers("U1", ["S1"])
        self._set_peers("U2", ["S1"])

        self._set_peers("S1", ["U1", "U2", "B1", "B2"])

        self._set_peers("B1", ["S1", "SAT1", "SAT2"])
        self._set_peers("B2", ["S1", "SAT1", "SAT2"])

        self._set_peers("SAT1", ["B1", "B2", "BS"])
        self._set_peers("SAT2", ["B1", "B2", "BS"])

        self._set_peers("BS", ["SAT1", "SAT2"])

        for entity in self.entities.values():
            print(
                f"{entity.name:5s}  role={entity.role:5s}  "
                f"ID={entity.identifier[:20]}..."
            )

    def _set_peers(self, entity_name: str, peers: List[str]) -> None:
        self.entities[entity_name].peers = list(peers)

    # -----------------------------------------------------------------------
    # Registration phase
    # -----------------------------------------------------------------------

    def register_entity(self, entity_name: str) -> str:
        """
        Create the registration material for one entity.

            RID_i   = H(ID_i || PU_i || PK_i)
            theta_i = H(RID_i || PU_i)

        The paper maintains a registered-ID set R.  An entity is therefore
        inserted once in R, while the resulting registration material is
        shared with each communicating peer.
        """
        entity = self.entities[entity_name]

        rid = h(
            entity.identifier,
            canonical_point(entity.public_key),
            entity.private_key,
        )
        theta = h(rid, canonical_point(entity.public_key))

        # Keep the registration value local for later distribution.
        entity.registered["_RID"] = rid
        entity.registered["_THETA"] = theta

        if rid not in self.registration_set:
            self.registration_set.add(rid)
            print(
                f"[REGISTERED] {entity_name:5s}  "
                f"RID={rid[:16]}..."
            )

        return rid

    def register_link(self, entity_name: str, peer_name: str) -> bool:
        """
        Distribute an entity's {RID, PU, theta} to one peer and validate theta.
        """
        entity = self.entities[entity_name]
        peer = self.entities[peer_name]

        rid = entity.registered.get("_RID")
        theta = entity.registered.get("_THETA")

        if rid is None or theta is None:
            rid = self.register_entity(entity_name)
            theta = entity.registered["_THETA"]

        theta_check = h(rid, canonical_point(entity.public_key))

        if theta_check != theta:
            print(
                f"[REG FAIL] {entity_name} -> {peer_name}: "
                "invalid theta"
            )
            return False

        peer.registered[entity_name] = rid

        session_id = h(
            "REG-SESSION",
            entity_name,
            peer_name,
            rid,
        )
        self.sessions[(entity_name, peer_name)] = session_id
        self.sessions[(peer_name, entity_name)] = session_id

        return True

    def register_network(self) -> None:
        print("\n=== REGISTRATION PHASE ===")

        # First create one RID for every entity.
        for name in self.entities:
            self.register_entity(name)

        # Then distribute registration data to immediate communication peers.
        direct_links = [
            ("U1", "S1"),
            ("U2", "S1"),
            ("S1", "B1"),
            ("S1", "B2"),
            ("B1", "SAT1"),
            ("B1", "SAT2"),
            ("B2", "SAT1"),
            ("B2", "SAT2"),
            ("SAT1", "BS"),
            ("SAT2", "BS"),
        ]

        for a, b in direct_links:
            self.register_link(a, b)

        print(
            f"Registration set R contains "
            f"{len(self.registration_set)} unique entity RIDs."
        )

    # -----------------------------------------------------------------------
    # Message helpers
    # -----------------------------------------------------------------------

    def _encrypt(
        self,
        sender: str,
        receiver: str,
        fields: List[str],
    ) -> bytes:
        plaintext = "|".join(fields)
        return self.crypto.encrypt(
            sender_private=self.entities[sender].private_key,
            receiver_public=self.entities[receiver].public_key,
            plaintext=plaintext,
        )

    def _decrypt(
        self,
        sender: str,
        receiver: str,
        ciphertext: bytes,
    ) -> List[str]:
        plaintext = self.crypto.decrypt(
            receiver_private=self.entities[receiver].private_key,
            sender_public=self.entities[sender].public_key,
            ciphertext=ciphertext,
        )
        return plaintext.split("|")

    def _fresh_timestamp(self) -> float:
        return time.time()

    @staticmethod
    def _within_window(t1: float, t2: float) -> bool:
        return abs(t2 - t1) < DELTA_T

    def _session(self, a: str, b: str) -> str:
        return h("SESSION", a, b, new_nonce())

    # -----------------------------------------------------------------------
    # Generic hop authentication
    # -----------------------------------------------------------------------

    def authenticate_pair(
        self,
        initiator: str,
        responder: str,
        nonce: Optional[int] = None,
    ) -> Tuple[bool, int]:
        """
        Implements the two-message handshake pattern appearing in each hop:

          1. initiator -> responder:
             ID_initiator, Nonce, TS
          2. responder -> initiator:
             ID_responder, Nonce, TS

        Returns:
            (success, nonce)
        """
        nonce = new_nonce() if nonce is None else nonce
        ts1 = self._fresh_timestamp()

        # M(request)
        request = self._encrypt(
            initiator,
            responder,
            [
                self.entities[initiator].identifier,
                str(nonce),
                f"{ts1:.9f}",
            ],
        )

        decoded = self._decrypt(initiator, responder, request)

        received_id = decoded[0]
        received_nonce = int(decoded[1])
        received_ts = float(decoded[2])

        if received_id != self.entities[initiator].identifier:
            print(
                f"[AUTH FAIL] {initiator}->{responder}: "
                "identity mismatch"
            )
            return False, nonce

        if received_nonce != nonce:
            print(
                f"[AUTH FAIL] {initiator}->{responder}: "
                "nonce mismatch"
            )
            return False, nonce

        # M(ack)
        ts2 = self._fresh_timestamp()
        acknowledgement = self._encrypt(
            responder,
            initiator,
            [
                self.entities[responder].identifier,
                str(nonce),
                f"{ts2:.9f}",
            ],
        )

        decoded_ack = self._decrypt(responder, initiator, acknowledgement)

        ack_id = decoded_ack[0]
        ack_nonce = int(decoded_ack[1])
        ack_ts = float(decoded_ack[2])

        if ack_id != self.entities[responder].identifier:
            print(
                f"[AUTH FAIL] {responder}->{initiator}: "
                "identity mismatch"
            )
            return False, nonce

        if ack_nonce != nonce:
            print(
                f"[AUTH FAIL] {responder}->{initiator}: "
                "nonce mismatch"
            )
            return False, nonce

        if not self._within_window(received_ts, ack_ts):
            print(
                f"[AUTH FAIL] {responder}<->{initiator}: "
                "timestamp window exceeded"
            )
            return False, nonce

        session_id = self._session(initiator, responder)
        self.sessions[(initiator, responder)] = session_id
        self.sessions[(responder, initiator)] = session_id

        print(
            f"[AUTH OK] {initiator} <-> {responder}  "
            f"nonce={nonce}  session={session_id[:16]}..."
        )
        return True, nonce

    # -----------------------------------------------------------------------
    # Protocol M1-M12
    # -----------------------------------------------------------------------

    def run_protocol(
        self,
        uws: str = "U1",
        sub: str = "S1",
        buoy: str = "B1",
        satellite: str = "SAT1",
    ) -> bool:
        """
        Full protocol sequence from the paper.

        M1-M3   : UWS <-> SUB and environmental data
        M4-M6   : SUB <-> B and aggregated environment/alerts
        M7-M9   : B <-> SAT and ENV/GPS
        M10-M12 : SAT <-> BS and ENV/ALERTS/GPS/LOGS
        """
        print("\n=== MUTUAL AUTHENTICATION / DATA PHASE ===")
        print(
            f"Path: {uws} -> {sub} -> {buoy} -> "
            f"{satellite} -> BS"
        )

        # ------------------------------
        # M1: UWS -> SUB
        # ------------------------------
        nonce_uws = new_nonce()
        ts1 = self._fresh_timestamp()

        m1 = self._encrypt(
            uws,
            sub,
            [
                self.entities[uws].identifier,
                str(nonce_uws),
                f"{ts1:.9f}",
            ],
        )
        d1 = self._decrypt(uws, sub, m1)

        if d1[0] != self.entities[uws].identifier:
            return self._fail("M1 identity")
        if int(d1[1]) != nonce_uws:
            return self._fail("M1 nonce")

        print("M1  UWS  -> SUB   authentication request")

        # ------------------------------
        # M2: SUB -> UWS
        # ------------------------------
        ts2 = self._fresh_timestamp()
        m2 = self._encrypt(
            sub,
            uws,
            [
                self.entities[sub].identifier,
                str(nonce_uws),
                f"{ts2:.9f}",
            ],
        )
        d2 = self._decrypt(sub, uws, m2)

        if d2[0] != self.entities[sub].identifier:
            return self._fail("M2 identity")
        if int(d2[1]) != nonce_uws:
            return self._fail("M2 nonce")
        if not self._within_window(float(d1[2]), float(d2[2])):
            return self._fail("M2 timestamp")

        self.sessions[(uws, sub)] = self._session(uws, sub)
        self.sessions[(sub, uws)] = self.sessions[(uws, sub)]

        print("M2  SUB  -> UWS   acknowledgement")
        print("     UWS <-> SUB session established")

        # ------------------------------
        # M3: UWS -> SUB (sensor data)
        # ------------------------------
        sensor = self._sensor_data()
        ts3 = self._fresh_timestamp()

        m3 = self._encrypt(
            uws,
            sub,
            [
                self.entities[uws].identifier,
                str(sensor["Temp"]),
                str(sensor["Press"]),
                str(sensor["CurrVel"]),
                str(sensor["Sal"]),
                f"{ts3:.9f}",
            ],
        )
        d3 = self._decrypt(uws, sub, m3)

        if d3[0] != self.entities[uws].identifier:
            return self._fail("M3 identity")

        env = {
            "Temp": float(d3[1]),
            "Press": float(d3[2]),
            "CurrVel": float(d3[3]),
            "Sal": float(d3[4]),
        }

        print(
            "M3  UWS  -> SUB   sensor data "
            f"{env}"
        )
        print("     SUB aggregates ENV =", env)

        # ------------------------------
        # M4: SUB -> B
        # ------------------------------
        nonce_sub = new_nonce()
        ts4 = self._fresh_timestamp()

        m4 = self._encrypt(
            sub,
            buoy,
            [
                self.entities[sub].identifier,
                str(nonce_sub),
                f"{ts4:.9f}",
            ],
        )
        d4 = self._decrypt(sub, buoy, m4)

        if d4[0] != self.entities[sub].identifier:
            return self._fail("M4 identity")
        if int(d4[1]) != nonce_sub:
            return self._fail("M4 nonce")

        print("M4  SUB  -> B     authentication request")

        # ------------------------------
        # M5: B -> SUB
        # ------------------------------
        ts5 = self._fresh_timestamp()
        m5 = self._encrypt(
            buoy,
            sub,
            [
                self.entities[buoy].identifier,
                str(nonce_sub),
                f"{ts5:.9f}",
            ],
        )
        d5 = self._decrypt(buoy, sub, m5)

        if d5[0] != self.entities[buoy].identifier:
            return self._fail("M5 identity")
        if int(d5[1]) != nonce_sub:
            return self._fail("M5 nonce")
        if not self._within_window(float(d4[2]), float(d5[2])):
            return self._fail("M5 timestamp")

        self.sessions[(sub, buoy)] = self._session(sub, buoy)
        self.sessions[(buoy, sub)] = self.sessions[(sub, buoy)]

        print("M5  B     -> SUB   acknowledgement")
        print("     SUB <-> B session established")

        # ------------------------------
        # M6: SUB -> B (ENV + alerts)
        # ------------------------------
        alerts = [
            "jamming",
            "spoofing",
            "eavesdropping",
        ]
        ts6 = self._fresh_timestamp()

        m6 = self._encrypt(
            sub,
            buoy,
            [
                self.entities[sub].identifier,
                str(env["Temp"]),
                str(env["Press"]),
                str(env["CurrVel"]),
                str(env["Sal"]),
                ",".join(alerts),
                f"{ts6:.9f}",
            ],
        )
        d6 = self._decrypt(sub, buoy, m6)

        if d6[0] != self.entities[sub].identifier:
            return self._fail("M6 identity")

        print(
            "M6  SUB  -> B     ENV + alerts "
            f"{alerts}"
        )

        # ------------------------------
        # M7: B -> SAT
        # ------------------------------
        nonce_b = new_nonce()
        ts7 = self._fresh_timestamp()

        m7 = self._encrypt(
            buoy,
            satellite,
            [
                self.entities[buoy].identifier,
                str(nonce_b),
                f"{ts7:.9f}",
            ],
        )
        d7 = self._decrypt(buoy, satellite, m7)

        if d7[0] != self.entities[buoy].identifier:
            return self._fail("M7 identity")
        if int(d7[1]) != nonce_b:
            return self._fail("M7 nonce")

        print("M7  B     -> SAT   authentication request")

        # ------------------------------
        # M8: SAT -> B
        # ------------------------------
        ts8 = self._fresh_timestamp()
        m8 = self._encrypt(
            satellite,
            buoy,
            [
                self.entities[satellite].identifier,
                str(nonce_b),
                f"{ts8:.9f}",
            ],
        )
        d8 = self._decrypt(satellite, buoy, m8)

        if d8[0] != self.entities[satellite].identifier:
            return self._fail("M8 identity")
        if int(d8[1]) != nonce_b:
            return self._fail("M8 nonce")
        if not self._within_window(float(d7[2]), float(d8[2])):
            return self._fail("M8 timestamp")

        self.sessions[(buoy, satellite)] = self._session(buoy, satellite)
        self.sessions[(satellite, buoy)] = self.sessions[(buoy, satellite)]

        print("M8  SAT  -> B     acknowledgement")
        print("     B <-> SAT session established")

        # ------------------------------
        # M9: B -> SAT (ENV + alerts + GPS)
        # ------------------------------
        gps = self._gps_data()
        ts9 = self._fresh_timestamp()

        m9 = self._encrypt(
            buoy,
            satellite,
            [
                self.entities[buoy].identifier,
                str(env["Temp"]),
                str(env["Press"]),
                str(env["CurrVel"]),
                str(env["Sal"]),
                ",".join(alerts),
                str(gps["lat"]),
                str(gps["lon"]),
                f"{ts9:.9f}",
            ],
        )
        d9 = self._decrypt(buoy, satellite, m9)

        if d9[0] != self.entities[buoy].identifier:
            return self._fail("M9 identity")

        print(
            "M9  B     -> SAT   ENV + alerts + GPS "
            f"{gps}"
        )

        # ------------------------------
        # M10: SAT -> BS
        # ------------------------------
        nonce_sat = new_nonce()
        ts10 = self._fresh_timestamp()

        m10 = self._encrypt(
            satellite,
            "BS",
            [
                self.entities[satellite].identifier,
                str(nonce_sat),
                f"{ts10:.9f}",
            ],
        )
        d10 = self._decrypt(satellite, "BS", m10)

        if d10[0] != self.entities[satellite].identifier:
            return self._fail("M10 identity")
        if int(d10[1]) != nonce_sat:
            return self._fail("M10 nonce")

        print("M10 SAT  -> BS    authentication request")

        # ------------------------------
        # M11: BS -> SAT
        # ------------------------------
        ts11 = self._fresh_timestamp()
        m11 = self._encrypt(
            "BS",
            satellite,
            [
                self.entities["BS"].identifier,
                str(nonce_sat),
                f"{ts11:.9f}",
            ],
        )
        d11 = self._decrypt("BS", satellite, m11)

        if d11[0] != self.entities["BS"].identifier:
            return self._fail("M11 identity")
        if int(d11[1]) != nonce_sat:
            return self._fail("M11 nonce")
        if not self._within_window(float(d10[2]), float(d11[2])):
            return self._fail("M11 timestamp")

        self.sessions[(satellite, "BS")] = self._session(satellite, "BS")
        self.sessions[("BS", satellite)] = self.sessions[(satellite, "BS")]

        print("M11 BS    -> SAT   acknowledgement")
        print("     SAT <-> BS session established")

        # ------------------------------
        # M12: SAT -> BS (final data package)
        # ------------------------------
        logs = self._mission_logs()
        ts12 = self._fresh_timestamp()

        m12 = self._encrypt(
            satellite,
            "BS",
            [
                self.entities[satellite].identifier,
                str(env["Temp"]),
                str(env["Press"]),
                str(env["CurrVel"]),
                str(env["Sal"]),
                ",".join(alerts),
                str(gps["lat"]),
                str(gps["lon"]),
                logs,
                f"{ts12:.9f}",
            ],
        )
        d12 = self._decrypt(satellite, "BS", m12)

        if d12[0] != self.entities[satellite].identifier:
            return self._fail("M12 identity")

        final_payload = {
            "Temp": float(d12[1]),
            "Press": float(d12[2]),
            "CurrVel": float(d12[3]),
            "Sal": float(d12[4]),
            "Alerts": d12[5].split(","),
            "GPS": {
                "lat": float(d12[6]),
                "lon": float(d12[7]),
            },
            "LOGS": d12[8],
        }

        print("M12 SAT  -> BS    final mission package")
        print("     BS received:")
        print(f"       ENV    = {final_payload['Temp']}, "
              f"{final_payload['Press']}, "
              f"{final_payload['CurrVel']}, "
              f"{final_payload['Sal']}")
        print(f"       Alerts = {final_payload['Alerts']}")
        print(f"       GPS    = {final_payload['GPS']}")
        print(f"       LOGS   = {final_payload['LOGS']}")

        print("\n=== PROTOCOL COMPLETE: SUCCESS ===")
        return True

    # -----------------------------------------------------------------------
    # Fallback architecture
    # -----------------------------------------------------------------------

    def choose_peer(
        self,
        current: str,
        candidates: List[str],
        unavailable: Optional[set[str]] = None,
    ) -> Optional[str]:
        """
        Paper fallback behavior:
          - SUB may reauthenticate with another registered buoy.
          - B may use another registered satellite.
        """
        unavailable = unavailable or set()

        for peer in candidates:
            if peer not in unavailable and peer in self.entities[current].peers:
                return peer

        return None

    # -----------------------------------------------------------------------
    # Example data generation
    # -----------------------------------------------------------------------

    @staticmethod
    def _sensor_data() -> Dict[str, float]:
        # The paper defines the four sensed quantities; the simulator uses
        # representative sample values only.
        return {
            "Temp": 22.4,
            "Press": 3.1,
            "CurrVel": 1.2,
            "Sal": 35.6,
        }

    @staticmethod
    def _gps_data() -> Dict[str, float]:
        return {
            "lat": 17.3850,
            "lon": 78.4867,
        }

    @staticmethod
    def _mission_logs() -> str:
        return "mission=UWC-DEMO,status=nominal,events=0"

    @staticmethod
    def _fail(reason: str) -> bool:
        print(f"[PROTOCOL FAIL] {reason}")
        return False


# ---------------------------------------------------------------------------
# Standalone demonstration
# ---------------------------------------------------------------------------

def main() -> int:
    protocol = UWCNProtocol()
    protocol.register_network()

    ok = protocol.run_protocol(
        uws="U1",
        sub="S1",
        buoy="B1",
        satellite="SAT1",
    )

    print("\n=== REGISTERED RID COUNT ===")
    print(len(protocol.registration_set))

    print("\n=== ESTABLISHED SESSIONS ===")
    for (a, b), sid in sorted(protocol.sessions.items()):
        print(f"{a:5s} <-> {b:5s} : {sid[:20]}...")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
