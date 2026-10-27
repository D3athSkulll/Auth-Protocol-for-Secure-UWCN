"""protocol.py - the UWC authentication protocol of Rupa et al., IEEE IoT-J 2025 ("IoT"), Sec. IV, on top of PEECC [18].

Five entity kinds UWS, SUB, B (buoy), SAT, BS in the chain UWS <-> SUB <-> B <-> SAT <-> BS.
    IoT Sec. IV-A  initialization : key pair (PK_i, PU_i = PK_i * B) in C, ID_i = H(PU_i || E || DeviceSerial)
    IoT Sec. IV-B  registration   : RID_i = H(ID_i || PU_i || PK_i), v_i = H(RID_i || PU_i), registry R
    IoT Sec. IV-C  authentication : M1-M12, every message PEECC-encrypted with the receiver's public key
    IoT Sec. IV-D  fallback       : preregistered fallback peers, re-authentication of mobile nodes (M1-M3)
    IoT Sec. IV-E  key management : revocation list from the BS, ID bound to the device serial

All elliptic-curve and modular arithmetic runs in C (peecc.dll / libpeecc.so, `make lib`), loaded with ctypes.
Hashing is SHA-256 (hashlib), truncated to the paper's field sizes. Time is simulated (class Clock); the computation
time of each crypto call is the real measured time of the C code and is added to the simulated timeline.
"""
import ctypes
import hashlib
import hmac
import logging
import os
import random
import secrets
import struct
import time
from collections import Counter, deque
from dataclasses import dataclass, field

log = logging.getLogger("uwc")

# Field sizes in bytes (IoT Sec. VI-A: 64-bit identities, 64-bit nonces, 8-bit timestamps, 160-bit hashes).
ID_BYTES, NONCE_BYTES, TS_BYTES, HASH_BYTES = 8, 8, 1, 20
KINDS = ("UWS", "SUB", "B", "SAT", "BS")

# Channel model (IoT Sec. VI-A): 10 kbps acoustic links, sound speed 1500 m/s.
BITRATE, SOUND_SPEED = 10_000.0, 1500.0

# 8-bit timestamp (paper gap): one tick = 50 ms, so the counter wraps every 256 * 0.05 = 12.8 s.
TICK, TS_MOD = 0.05, 256
# Adaptive delta-T (IoT Sec. V): rolling average of recent accepted delays, dT = FACTOR * avg + MARGIN, clamped.
# The margin (1 s) covers the longest legitimate one-way delay (1000 m / 1500 m/s + a 2-block message at 10 kbps
# = 0.87 s) even when the average comes from short links; dT stays far below the 12.8 s timestamp wrap.
DT_INIT, DT_MIN, DT_MAX, DT_FACTOR, DT_MARGIN, DT_WINDOW = 2.0, 1.0, 6.0, 2.0, 1.0, 8


# PEECC mode flags (peecc.c): hardened K + point validation, and compressed points (33 instead of 64 bytes).
HARDENED, COMPRESSED = 1, 2


def mode_of(hardened, compressed=None):
    """Mode flags. The improved scheme uses both deviations; compressed defaults to `hardened`."""
    return (HARDENED if hardened else 0) | (COMPRESSED if (hardened if compressed is None else compressed) else 0)


# Energy model (IoT Sec. VI-D values). The paper charges 24 uJ per ECC operation; we charge it per 256-bit scalar
# multiplication and scale with the scalar length, since double-and-add work grows linearly with the bits of K
# (paper-exact K has 2029 bits). The flat per-operation figure is reported next to it.
E_ECC_256, E_HASH, E_ENC = 24.0, 6.0, 3.2


# ============================================================================= PEECC library (ctypes)
class Peecc:
    """ctypes wrapper of the peecc_* API in peecc.c. Byte formats: scalar 32 B, point x||y 64 B (or 0x02/03||x
    33 B compressed), block C1||C2 128 B (66 B compressed). `mode` is an int of the flags above (a bool = hardened)."""

    def __init__(self, path=None):
        here = os.path.dirname(os.path.abspath(__file__))
        names = [path] if path else [os.path.join(here, n) for n in ("peecc.dll", "libpeecc.so")]
        found = [n for n in names if n and os.path.exists(n)]
        if not found:
            raise FileNotFoundError("PEECC library not found - build it with `make lib`")
        self.path = found[0]
        L = self.lib = ctypes.CDLL(self.path)
        u8p, sz = ctypes.c_char_p, ctypes.c_size_t
        L.peecc_ct_size.argtypes, L.peecc_ct_size.restype = [sz, ctypes.c_int], sz
        L.peecc_block_bytes.argtypes, L.peecc_block_bytes.restype = [ctypes.c_int], ctypes.c_int
        L.peecc_max_block.restype = ctypes.c_int
        L.peecc_keygen.argtypes = [u8p, u8p]
        L.peecc_encrypt.argtypes = [u8p, sz, u8p, ctypes.c_int, u8p]
        L.peecc_decrypt.argtypes = [u8p, sz, u8p, ctypes.c_int, u8p]
        L.peecc_eavesdrop.argtypes = [u8p, sz, u8p, ctypes.c_int, u8p]
        L.peecc_pentatope_K.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, sz]
        L.peecc_bench.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_double)]
        L.peecc_bench.restype = None
        self.block = L.peecc_max_block()

    def ct_size(self, n, mode=0):
        return self.lib.peecc_ct_size(n, int(mode))

    def block_bytes(self, mode=0):
        """Bytes of one ciphertext block: 128, or 66 with compressed points."""
        return self.lib.peecc_block_bytes(int(mode))

    def keygen(self):
        """[18] Sec. 3.1: (private d, public Pub = d*B)."""
        d, pub = ctypes.create_string_buffer(32), ctypes.create_string_buffer(64)
        self.lib.peecc_keygen(d, pub)
        return d.raw, pub.raw

    def encrypt(self, msg, pub, mode):
        """[18] Sec. 3.2, split into 29-byte blocks. Returns the ciphertext, or None if Pub is rejected (hardened)."""
        out = ctypes.create_string_buffer(self.ct_size(len(msg), mode))
        return out.raw if self.lib.peecc_encrypt(msg, len(msg), pub, int(mode), out) else None

    def decrypt(self, ct, d, mode):
        """[18] Sec. 3.3 block by block. Returns the plaintext, or None if rejected / not decodable."""
        out = ctypes.create_string_buffer(max(1, len(ct) // self.block_bytes(mode) * self.block))
        n = self.lib.peecc_decrypt(ct, len(ct), d, int(mode), out)
        return out.raw[:n] if n >= 0 else None

    def eavesdrop(self, ct, pub, mode=0):
        """Keyless attacker: C2 - K_paper*Pub per block. Returns the plaintext it reads, or None."""
        out = ctypes.create_string_buffer(max(1, len(ct) // self.block_bytes(mode) * self.block))
        n = self.lib.peecc_eavesdrop(ct, len(ct), pub, int(mode), out)
        return out.raw[:n] if n >= 0 else None

    def pentatope_K(self, x):
        """[18] Sec. 3.2 Steps 2-3 in C: (S, K) for an integer x."""
        size = 8 * len(str(x)) + 64
        s, k = ctypes.create_string_buffer(size), ctypes.create_string_buffer(size)
        if not self.lib.peecc_pentatope_K(str(x).encode(), s, k, size):
            raise ValueError("pentatope_K failed")
        return int(s.value), int(k.value)

    def bench(self, iters, mode):
        """Measured mean ms (keygen, encrypt, decrypt) of one 11-byte block, from peecc_bench in C."""
        ms = (ctypes.c_double * 3)()
        self.lib.peecc_bench(iters, int(mode), ms)
        return tuple(ms)


# ============================================================================= helpers
def H(*parts, n=HASH_BYTES):
    """One-way hash (IoT Sec. III-B): SHA-256 over the concatenation, truncated to n bytes."""
    return hashlib.sha256(b"".join(parts)).digest()[:n]


def ts8(t):
    """8-bit timestamp of simulated time t (paper: 8-bit TS)."""
    return int(t / TICK) % TS_MOD


def ts_age(ts, now):
    """Seconds between an 8-bit timestamp and the current time, modulo the 12.8 s wrap."""
    return ((ts8(now) - ts) % TS_MOD) * TICK


class Clock:
    """Simulated time in seconds, shared by all entities (synchronized clocks are assumed, as in the paper)."""

    def __init__(self):
        self.now = 0.0


class DelayWindow:
    """IoT Sec. V adaptive delta-T: rolling average of recent accepted inter-node delays."""

    def __init__(self):
        self.recent = deque(maxlen=DT_WINDOW)

    def dt(self):
        if not self.recent:
            return DT_INIT
        return min(DT_MAX, max(DT_MIN, DT_FACTOR * sum(self.recent) / len(self.recent) + DT_MARGIN))

    def observe(self, delay):
        self.recent.append(delay)


# Payload encodings (the paper gives no sizes for ENV, Alerts, GPS or LOGS; these are our choices).
def pack_env(env):
    return struct.pack(">4f", env["Temp"], env["Press"], env["CurrVel"], env["Sal"])


def unpack_env(b):
    return dict(zip(("Temp", "Press", "CurrVel", "Sal"), struct.unpack(">4f", b[:16]))), b[16:]


def pack_var(b):
    return bytes([len(b)]) + b


def unpack_var(b):
    return b[1:1 + b[0]], b[1 + b[0]:]


@dataclass
class Packet:
    label: str          # M1 ... M12, REG, ...
    src: str            # claimed sender (link-layer address, NOT authenticated)
    dst: str
    ct: bytes           # what actually travels (PEECC ciphertext, or plaintext for registration)
    sent_at: float = 0.0
    extra_delay: float = 0.0
    fields: dict = field(default_factory=dict)   # plaintext, for the trace only - receivers never read it


# ============================================================================= entities
class Entity:
    """One UWS, SUB, B, SAT or BS."""

    def __init__(self, name, kind, net):
        self.name, self.kind, self.net = name, kind, net
        self.serial = secrets.token_bytes(8)       # DeviceSerial (IoT Sec. IV-E-3)
        self.R = {}                 # registry R: RID -> PU (hash table)
        self.reg_pub = set()        # public keys registered with this entity (same entries as R, indexed by PU)
        self.directory = {}         # ID -> (name, PU): public keys distributed by the BS (IoT Sec. IV-E-3)
        self.sessions = {}          # peer name -> {"since": t, "role": "initiator"/"responder"}
        self.used_nonces = set()
        self.window = DelayWindow()
        self.revoked = set()        # IDs on the verified revocation list
        self.fallback = {}          # kind -> [preregistered fallback peer names] (IoT Sec. IV-D)
        self.ops = Counter()        # ecc_mul, ecc_bits (sum of scalar lengths), hash, enc, dec
        self.cpu_ms = 0.0           # measured computation time of this entity
        self.alive = True
        self.respond_delay = 0.0    # processing delay injected for fallback scenarios (a "delayed" node)
        self.env_in = []            # ENV values received from children (for aggregation)

    # ---------------------------------------------------------------- IoT Sec. IV-A
    def initialize(self):
        """IoT Sec. IV-A Steps 3-6: PK_i random, PU_i = PK_i * B (C), ID_i = H(PU_i || E || DeviceSerial)."""
        t0 = time.perf_counter()
        self.PK, self.PU = self.net.lib.keygen()
        self.ops["ecc_mul"] += 1
        self.ops["ecc_bits"] += 256
        self.ID = H(self.PU, self.kind.encode(), self.serial, n=ID_BYTES)
        self.ops["hash"] += 1
        self.cpu_ms += (time.perf_counter() - t0) * 1000
        return self.ID, self.PU                       # M_i = (ID_i, PU_i)

    def crypto(self, fn, *args):
        """Run a C call, add its measured time to this entity and to the simulated clock."""
        t0 = time.perf_counter()
        out = fn(*args)
        ms = (time.perf_counter() - t0) * 1000
        self.cpu_ms += ms
        self.net.clock.now += ms / 1000
        return out

    def encrypt_for(self, peer_pu, plain):
        out = self.crypto(self.net.lib.encrypt, plain, peer_pu, self.net.mode)
        blocks = len(out) // self.net.block_bytes if out else 0
        self.ops["enc"] += 1
        self.ops["ecc_mul"] += 2 * blocks             # C1 = K*B and K*Pub per block
        self.ops["ecc_bits"] += 2 * blocks * self.net.k_bits
        return out

    def decrypt_own(self, ct):
        out = self.crypto(self.net.lib.decrypt, ct, self.PK, self.net.mode)
        blocks = len(ct) // self.net.block_bytes
        self.ops["dec"] += 1
        self.ops["ecc_mul"] += blocks                 # d*C1 per block
        self.ops["ecc_bits"] += 256 * blocks
        return out

    def energy_uj(self, flat=False):
        """Energy with the paper's per-operation values. flat=True: 24 uJ per ECC operation as in the paper;
        otherwise 24 uJ per 256 scalar bits (work of double-and-add grows with the length of K)."""
        o = self.ops
        ecc = o["ecc_mul"] * E_ECC_256 if flat else o["ecc_bits"] / 256 * E_ECC_256
        return ecc + o["hash"] * E_HASH + (o["enc"] + o["dec"]) * E_ENC

    # ---------------------------------------------------------------- IoT Sec. IV-B
    def registration_message(self):
        """IoT Sec. IV-B Steps 1-2: RID_i = H(ID_i || PU_i || PK_i), v_i = H(RID_i || PU_i), M_i = {RID_i, PU_i, v_i}."""
        self.RID = H(self.ID, self.PU, self.PK)
        self.vartheta = H(self.RID, self.PU)
        self.ops["hash"] += 2
        return self.RID, self.PU, self.vartheta

    def receive_registration(self, rid, pu, v):
        """IoT Sec. IV-B Steps 3-5 at entity j. Returns VALID, INVALID, DUPLICATE, REVOKED or UNKNOWN."""
        self.ops["hash"] += 1
        if H(rid, pu) != v:
            return "INVALID"                            # Step 3: v_j != v_i
        owner = next((i for i, (_, p) in self.directory.items() if p == pu), None)
        if owner is None:
            return "UNKNOWN"                            # IoT Sec. IV-E-3: PU not in the BS-distributed directory
        if owner in self.revoked:
            return "REVOKED"                            # IoT Sec. IV-E-2
        if rid in self.R:
            return "DUPLICATE"                          # Step 4
        self.R[rid] = pu                                # Step 5: add to R, session S_ij may be created
        self.reg_pub.add(pu)
        return "VALID"

    def storage_bytes(self):
        """Registry storage: 20 bytes per registered 160-bit RID (IoT Sec. IV-B estimate 20 x k)."""
        return HASH_BYTES * len(self.R)


# ============================================================================= network and protocol
class Network:
    """Entities, links and the protocol steps. `trace` (if set) is called with one dict per protocol event."""

    def __init__(self, lib, hardened=False, seed=1, compressed=None):
        self.lib, self.hardened = lib, hardened
        self.mode = mode_of(hardened, compressed)          # the improved scheme also compresses points
        self.compressed = bool(self.mode & COMPRESSED)
        self.block_bytes = lib.block_bytes(self.mode)
        self.k_bits = 256 if hardened else 2029            # length of K: (S^2+S+41) mod N vs S^2+S+41 from B_x
        self.clock = Clock()
        self.nodes = {}
        self.dist = {}               # frozenset({a, b}) -> metres
        self.rng = random.Random(seed)
        self.mgmt_key = secrets.token_bytes(32)    # management key known to all trusted nodes (IoT Sec. IV-E-2)
        self.trace = None
        self.messages = []           # every delivered protocol message (for metrics)
        self.sessions_created = 0
        self.events = Counter()

    # ---------------------------------------------------------------- topology
    def add(self, name, kind):
        self.nodes[name] = Entity(name, kind, self)
        return self.nodes[name]

    def link(self, a, b, metres=None):
        self.dist[frozenset((a, b))] = metres if metres is not None else self.rng.uniform(100, 1000)

    def emit(self, kind, **kw):
        kw["t"] = self.clock.now
        kw["block"] = self.block_bytes
        if self.trace:
            self.trace(kind, kw)

    # ---------------------------------------------------------------- IoT Sec. IV-A, IV-E-3
    def initialize(self):
        """IoT Sec. IV-A for every entity; the BS distributes all (ID, PU) pairs over a trusted link (IV-E-3)."""
        for e in self.nodes.values():
            e.initialize()
            log.info("[INIT] %-6s %-3s ID=%s PU=%s..", e.name, e.kind, e.ID.hex(), e.PU.hex()[:16])
        table = {e.ID: (e.name, e.PU) for e in self.nodes.values()}
        for e in self.nodes.values():
            e.directory = dict(table)

    # ---------------------------------------------------------------- IoT Sec. IV-B
    def register(self, i, j, msg=None):
        """Entity i registers with entity j (IoT Sec. IV-B). msg overrides the registration message (attacks)."""
        a, b = self.nodes[i], self.nodes[j]
        rid, pu, v = msg if msg else a.registration_message()
        status = b.receive_registration(rid, pu, v)
        self.emit("register", src=i, dst=j, rid=rid, status=status, bits=8 * (len(rid) + len(pu) + len(v)))
        log.info("[REGISTER] %s -> %s RID=%s..: %s", i, j, rid.hex()[:16], status)
        return status

    def register_pair(self, i, j):
        return self.register(i, j), self.register(j, i)

    # ---------------------------------------------------------------- IoT Sec. IV-E-2
    def issue_revocation(self, names):
        """BS issues an authenticated revocation list; every entity verifies it before using it (IoT Sec. IV-E-2)."""
        ids = sorted(self.nodes[n].ID for n in names)
        tag = hmac.new(self.mgmt_key, b"".join(ids), hashlib.sha256).digest()
        return ids, tag

    def broadcast_revocation(self, ids, tag):
        ok = hmac.compare_digest(tag, hmac.new(self.mgmt_key, b"".join(ids), hashlib.sha256).digest())
        for e in self.nodes.values():
            if ok:
                e.revoked |= set(ids)
            e.ops["hash"] += 1
        log.info("[REGISTER] revocation list of %d IDs: %s", len(ids), "accepted" if ok else "REJECTED (bad tag)")
        return ok

    # ---------------------------------------------------------------- transport
    def transmit(self, pkt):
        """Move a packet over the acoustic link: transmission time + propagation delay (+ injected delay)."""
        metres = self.dist.get(frozenset((pkt.src, pkt.dst)), 500.0)
        tx, prop = 8 * len(pkt.ct) / BITRATE, metres / SOUND_SPEED
        pkt.sent_at = self.clock.now
        self.clock.now += tx + prop + pkt.extra_delay
        self.messages.append(dict(label=pkt.label, src=pkt.src, dst=pkt.dst, bytes=len(pkt.ct), tx=tx, prop=prop,
                                  fields=pkt.fields, hop=frozenset((pkt.src, pkt.dst))))
        return tx, prop

    # ---------------------------------------------------------------- IoT Sec. IV-C, one hop
    def make_request(self, I, R, label):
        """M1/M4/M7/M10: E{PU_R, ID_I || Nonce_I || TS}."""
        a, b = self.nodes[I], self.nodes[R]
        nonce, ts = secrets.token_bytes(NONCE_BYTES), ts8(self.clock.now)
        plain = a.ID + nonce + bytes([ts])
        ct = a.encrypt_for(b.PU, plain)
        return Packet(label, I, R, ct, fields={"ID_" + a.kind: a.ID.hex(), "Nonce_" + a.kind: nonce.hex(), "TS": ts}), nonce, ts

    def handle_request(self, R, pkt):
        """Responder checks the request: decrypt, known + registered + not revoked, nonce unused, |now - TS| < dT."""
        b, now = self.nodes[R], self.clock.now
        plain = b.decrypt_own(pkt.ct)
        checks = []
        if plain is None or len(plain) != ID_BYTES + NONCE_BYTES + TS_BYTES:
            return False, "decryption failed", None, checks
        idi, nonce, ts = plain[:ID_BYTES], plain[ID_BYTES:-1], plain[-1]
        known = idi in b.directory and b.directory[idi][1] in b.reg_pub
        checks.append(("ID registered", known))
        if not known:
            return False, "unknown or unregistered ID", None, checks
        checks.append(("ID not revoked", idi not in b.revoked))
        if idi in b.revoked:
            return False, "ID on revocation list", None, checks
        fresh_n = nonce not in b.used_nonces
        checks.append(("nonce unused", fresh_n))
        if not fresh_n:
            return False, "nonce already used (replay)", None, checks
        age, dt = ts_age(ts, now), b.window.dt()
        checks.append(("|now - TS| = %.2f s < dT = %.2f s" % (age, dt), age < dt))
        if age >= dt:
            return False, "stale timestamp (%.2f s >= %.2f s)" % (age, dt), None, checks
        b.used_nonces.add(nonce)
        b.window.observe(age)
        return True, "ok", (idi, nonce, ts), checks

    def make_response(self, R, I, label, nonce):
        """M2/M5/M8/M11: E{PU_I, ID_R || Nonce_I (echoed) || TS}."""
        a, b = self.nodes[I], self.nodes[R]
        self.clock.now += b.respond_delay
        ts = ts8(self.clock.now)
        ct = b.encrypt_for(a.PU, b.ID + nonce + bytes([ts]))
        return Packet(label, R, I, ct, fields={"ID_" + b.kind: b.ID.hex(), "Nonce (echo)": nonce.hex(), "TS": ts})

    def handle_response(self, I, R, pkt, nonce_sent, ts_sent):
        """Initiator checks: ID_R expected, Nonce_recv = Nonce_sent, |TS_resp - TS_req| < dT."""
        a, b = self.nodes[I], self.nodes[R]
        plain = a.decrypt_own(pkt.ct)
        checks = []
        if plain is None or len(plain) != ID_BYTES + NONCE_BYTES + TS_BYTES:
            return False, "decryption failed", checks
        idr, nonce, ts = plain[:ID_BYTES], plain[ID_BYTES:-1], plain[-1]
        checks.append(("ID_R is the expected peer", idr == b.ID))
        if idr != b.ID:
            return False, "unexpected responder ID", checks
        checks.append(("ID not revoked", idr not in a.revoked))
        if idr in a.revoked:
            return False, "ID on revocation list", checks
        checks.append(("Nonce_recv = Nonce_sent", nonce == nonce_sent))
        if nonce != nonce_sent:
            return False, "nonce mismatch", checks
        diff, dt = ((ts - ts_sent) % TS_MOD) * TICK, a.window.dt()
        checks.append(("|TS_resp - TS_req| = %.2f s < dT = %.2f s" % (diff, dt), diff < dt))
        if diff >= dt:
            return False, "response too late (%.2f s >= %.2f s)" % (diff, dt), checks
        a.window.observe(diff)
        return True, "ok", checks

    def make_data(self, I, R, label, payload, fields):
        """M3/M6/M9/M12: E{PU_R, ID_R || payload || TS}. (The paper puts the receiver's ID here, not the sender's.)"""
        a, b = self.nodes[I], self.nodes[R]
        ts = ts8(self.clock.now)
        ct = a.encrypt_for(b.PU, b.ID + payload + bytes([ts]))
        return Packet(label, I, R, ct, fields=dict({"ID_" + b.kind: b.ID.hex()}, **fields, TS=ts))

    def handle_data(self, R, pkt):
        """Receiver of M3/M6/M9/M12: decrypt, own ID, session with the (claimed) sender, fresh TS."""
        b = self.nodes[R]
        plain = b.decrypt_own(pkt.ct)
        checks = []
        if plain is None or len(plain) < ID_BYTES + TS_BYTES:
            return False, "decryption failed", None, checks
        checks.append(("ID is own ID", plain[:ID_BYTES] == b.ID))
        checks.append(("session with %s exists" % pkt.src, pkt.src in b.sessions))
        age, dt = ts_age(plain[-1], self.clock.now), b.window.dt()
        checks.append(("|now - TS| = %.2f s < dT = %.2f s" % (age, dt), age < dt))
        ok = all(c for _, c in checks)
        return ok, "ok" if ok else "data rejected", plain[ID_BYTES:-1], checks

    def create_session(self, x, peer, role):
        self.nodes[x].sessions[peer] = {"since": self.clock.now, "role": role}
        self.sessions_created += 1

    def authenticate_hop(self, I, R, labels, payload, fields):
        """One hop of IoT Sec. IV-C (e.g. Steps 1-4 for UWS-SUB): request, response, session, data message.
        Returns (ok, reason, seconds)."""
        t0 = self.clock.now
        a, b = self.nodes[I], self.nodes[R]
        req, nonce, ts = self.make_request(I, R, labels[0])
        self.transmit(req)
        if not b.alive:                                          # no answer: wait dT, then give up
            self.clock.now += a.window.dt()
            self.emit("timeout", src=I, dst=R, label=labels[0], wait=a.window.dt())
            log.info("[AUTH] %s %s -> %s: no response within dT = %.2f s", labels[0], I, R, a.window.dt())
            return False, "timeout", self.clock.now - t0
        ok, why, _, checks = self.handle_request(R, req)
        self.emit("message", pkt=req, ok=ok, why=why, checks=checks)
        log.info("[AUTH] %s %s -> %s %d bit: %s", labels[0], I, R, 8 * len(req.ct), why)
        if not ok:
            return False, why, self.clock.now - t0
        self.create_session(R, I, "responder")
        resp = self.make_response(R, I, labels[1], nonce)
        self.transmit(resp)
        ok, why, checks = self.handle_response(I, R, resp, nonce, ts)
        self.emit("message", pkt=resp, ok=ok, why=why, checks=checks)
        log.info("[AUTH] %s %s -> %s %d bit: %s", labels[1], R, I, 8 * len(resp.ct), why)
        if not ok:
            b.sessions.pop(I, None)
            return False, why, self.clock.now - t0
        self.create_session(I, R, "initiator")
        self.emit("session", a=I, b=R)
        log.info("[AUTH] session S_%s<->%s established", I, R)
        data = self.make_data(I, R, labels[2], payload, fields)
        self.transmit(data)
        ok, why, body, checks = self.handle_data(R, data)
        self.emit("message", pkt=data, ok=ok, why=why, checks=checks)
        log.info("[AUTH] %s %s -> %s %d bit: %s", labels[2], I, R, 8 * len(data.ct), why)
        if ok and labels[2] in ("M3", "M6"):
            b.env_in.append(unpack_env(body)[0])
        return ok, why, self.clock.now - t0

    def authenticate_with_fallback(self, I, primary, labels, payload, fields):
        """IoT Sec. IV-D: try the primary peer, then the preregistered fallback peers. Returns (peer, ok, seconds)."""
        t0 = self.clock.now
        kind = self.nodes[primary].kind
        for n, peer in enumerate([primary] + self.nodes[I].fallback.get(kind, [])):
            if n:
                self.emit("fallback", src=I, dst=peer, after=primary)
                log.info("[FALLBACK] %s re-authenticates with fallback peer %s", I, peer)
            ok, why, _ = self.authenticate_hop(I, peer, labels, payload, fields)
            if ok:
                return peer, True, self.clock.now - t0
        return None, False, self.clock.now - t0


# ============================================================================= payloads of M3, M6, M9, M12
def sample_env(rng):
    return {"Temp": round(rng.uniform(2, 25), 2), "Press": round(rng.uniform(1, 400), 1),
            "CurrVel": round(rng.uniform(0, 2), 2), "Sal": round(rng.uniform(30, 38), 2)}


def aggregate_env(envs):
    """SUB aggregates the ENV values of its UWS (IoT Sec. IV-C Step 4): mean of each field."""
    keys = ("Temp", "Press", "CurrVel", "Sal")
    return {k: round(sum(e[k] for e in envs) / len(envs), 3) for k in keys} if envs else {k: 0.0 for k in keys}


def data_payload(hop, env, alerts=b"", gps=(0.0, 0.0), logs=b""):
    """Plaintext payload (without ID and TS) of M3 (hop 1), M6 (hop 2), M9 (hop 3), M12 (hop 4)."""
    p, f = pack_env(env), {"ENV": env}
    if hop >= 2:
        p += pack_var(alerts); f["Alerts"] = alerts.decode()
    if hop >= 3:
        p += struct.pack(">2f", *gps); f["GPS"] = gps
    if hop >= 4:
        p += pack_var(logs); f["LOGS"] = logs.decode()
    return p, f


HOP_LABELS = {1: ("M1", "M2", "M3"), 2: ("M4", "M5", "M6"), 3: ("M7", "M8", "M9"), 4: ("M10", "M11", "M12")}


def build_fig1(lib, hardened=False, seed=1):
    """The redundant topology of IoT Fig. 1: S1-S18, SB1-SB6, B1-B3, SAT1-SAT3, BS, with fallback peers
    (SUB -> next buoy, B -> next satellite, UWS -> next SUB for mobility). All links are registered both ways."""
    net = Network(lib, hardened, seed)
    for i in range(1, 19): net.add("S%d" % i, "UWS")
    for i in range(1, 7): net.add("SB%d" % i, "SUB")
    for i in range(1, 4): net.add("B%d" % i, "B")
    for i in range(1, 4): net.add("SAT%d" % i, "SAT")
    net.add("BS", "BS")
    up = {}                                               # child -> [primary parent, fallback parent]
    for i in range(1, 19):
        sb = (i - 1) // 3 + 1
        up["S%d" % i] = ["SB%d" % sb, "SB%d" % (sb % 6 + 1)]
    for i in range(1, 7):
        b = (i - 1) // 2 + 1
        up["SB%d" % i] = ["B%d" % b, "B%d" % (b % 3 + 1)]
    for i in range(1, 4):
        up["B%d" % i] = ["SAT%d" % i, "SAT%d" % (i % 3 + 1)]
        up["SAT%d" % i] = ["BS"]
    for child, parents in up.items():
        for p in parents:
            net.link(child, p)
        if len(parents) > 1:
            net.nodes[child].fallback[net.nodes[parents[0]].kind] = parents[1:]
    net.up = up
    return net


def register_all(net):
    """IoT Sec. IV-B over every primary and fallback link, in both directions."""
    for child, parents in net.up.items():
        for p in parents:
            net.register_pair(child, p)


def path_to_bs(net, uws):
    """Primary path UWS -> SUB -> B -> SAT -> BS."""
    path = [uws]
    while path[-1] != "BS":
        path.append(net.up[path[-1]][0])
    return path
