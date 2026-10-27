#!/usr/bin/env python3
"""peecc_gui.py - presentation-style visual simulation of PEECC (reference [18]) and of an improved variant.

Tab 1  Pipeline        : the full process on secp256r1 with real 256-bit values (animated block diagram).
Tab 2  Toy curve       : the same algorithm on y^2 = x^3 + x + 1 (mod 23); every point and every k*B is visible.
Tab 3  Math walkthrough: node-by-node worked example on the toy curve, every number of the computation.
Tab 4  Improvements    : live, measured comparison "base paper [18] as specified" vs "improved scheme".
Tab 5  Metrics         : measured / counted performance metrics of both schemes (Python, plus C via peecc.dll).
Tab 6  Protocol        : the UWC protocol M1-M12 (protocol.py on peecc.dll) as a sequence diagram, with each
                         message's plaintext, ciphertext blocks, checks, and what a keyless eavesdropper reads.

Modes (the same two modes as peecc.c)
  paper-exact  : x = B_x, S = Pentatope(x), K = S^2 + S + 41, exactly as in [18] (peecc.c default)
  improved     : DEVIATION from [18] (peecc.c --hardened): the pentatope input x is a fresh secret random number per
                 message, K = (S^2 + S + 41) mod N, points are validated before use, and points are sent
                 compressed (02/03 || x, 33 instead of 64 bytes).

The mathematics is a pure-Python re-implementation of peecc.c.  `python peecc_gui.py --selftest` checks it against
the values printed by peecc.exe (C1 and P_m of "hello world").  Needs tkinter + matplotlib.
"""
import os
import secrets
import sys
import time

# ============================================================================= mathematics
class Curve:
    """Short Weierstrass curve y^2 = x^3 + a x + b over F_p with generator B of order N."""

    def __init__(self, p, a, b, B, N):
        self.p, self.a, self.b, self.B, self.N = p, a % p, b % p, B, N
        self.n_mul = self.n_dbl = self.n_add = 0     # operation counters (performance metrics)

    def on(self, P):
        return P is None or (P[1] * P[1] - (P[0] ** 3 + self.a * P[0] + self.b)) % self.p == 0

    def valid(self, P):
        """Point validation: coordinates in range and on the curve (the C code does NOT do this)."""
        return P is not None and 0 <= P[0] < self.p and 0 <= P[1] < self.p and self.on(P)

    def neg(self, P):
        return None if P is None else (P[0], (-P[1]) % self.p)

    def add(self, P, Q):
        p = self.p
        if P is None: return Q
        if Q is None: return P
        if P[0] == Q[0]:
            if (P[1] + Q[1]) % p == 0: return None
            self.n_dbl += 1
            lam = (3 * P[0] * P[0] + self.a) * pow(2 * P[1], -1, p) % p
        else:
            self.n_add += 1
            lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
        x = (lam * lam - P[0] - Q[0]) % p
        return (x, (lam * (P[0] - x) - P[1]) % p)

    def mul(self, k, P):
        self.n_mul += 1
        R = None
        for bit in bin(k)[2:]:
            R = self.add(R, R)
            if bit == "1":
                R = self.add(R, P)
        return R

    def rhs(self, x):
        return (x ** 3 + self.a * x + self.b) % self.p


REAL = Curve(
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF, -3,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551)


def pentatope(x):
    """[18] Sec. 3.2 Step 2: S = x(x+1)(x+2)(x+3)/24."""
    return x * (x + 1) * (x + 2) * (x + 3) // 24


def euler_K(s):
    """[18] Sec. 3.2 Step 3: K = S^2 + S + 41."""
    return s * s + s + 41


def koblitz_encode(E, data, kappa=256):
    """Bytes (or integer m) -> point as in peecc.c: m = 0x01||data, x = m*kappa + j, y = rhs^((p+1)/4)."""
    m = int.from_bytes(b"\x01" + data, "big") if isinstance(data, bytes) else data
    tries = []
    for j in range(kappa):
        x = m * kappa + j
        if x >= E.p:
            break
        r = E.rhs(x)
        y = pow(r, (E.p + 1) // 4, E.p)
        ok = y * y % E.p == r
        tries.append((j, x, ok))
        if ok:
            return m, tries, (x, y), j
    return m, tries, None, None


def koblitz_decode(E, P, kappa=256):
    if P is None:
        return None
    m = P[0] // kappa
    raw = m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")
    return raw[1:] if raw and raw[0] == 1 and len(raw) <= 30 else None


def short(v, n=14):
    h = "%x" % v
    return h if len(h) <= 2 * n + 3 else h[:n] + "..." + h[-n:]


def compress_hex(P, n=14):
    """Compressed form of a point as peecc.c sends it in the improved mode: 02 (y even) / 03 (y odd) || x."""
    return "O (infinity)" if P is None else "%02x | %s" % (3 if P[1] & 1 else 2, short(P[0], n))


def fmt_pt(P, n=14):
    return "O (infinity)" if P is None else "x = %s\ny = %s" % (short(P[0], n), short(P[1], n))


def hardened_K(E, x=None):
    """Improved mode (DEVIATION from [18], peecc.c make_K --hardened): the pentatope input x is a fresh secret random
    number in [1, N-1] instead of B_x; S = Pentatope(x), K = (S^2+S+41) mod N.  Returns (x, S, K).
    K = 0 mod N is skipped: a new draw, or for a given x (toy curves) the next x."""
    fixed = x is not None
    while True:
        if not fixed:
            x = secrets.randbelow(E.N - 1) + 1
        S = pentatope(x)
        k = euler_K(S) % E.N
        if k:
            return x, S, k
        x += 1


def scheme_scalar(E, improved):
    """The multiplier used for C1 = k*B and T = k*Pub.  paper-exact: public K; improved: K from a random x."""
    if improved:
        return hardened_K(E)[2]
    return euler_K(pentatope(E.B[0]))


def encrypt_point(E, Pm, Pub, improved, k=None):
    """Returns (k, C1, T, C2).  k may be given (to show how it was derived), otherwise it is drawn per mode."""
    k = scheme_scalar(E, improved) if k is None else k
    C1, T = E.mul(k, E.B), E.mul(k, Pub)
    return k, C1, T, E.add(Pm, T)


def decrypt_point(E, C1, C2, d, improved):
    """Receiver side.  The improved scheme rejects invalid points first (returns None)."""
    if improved and not (E.valid(C1) and E.valid(C2)):
        return None
    return E.add(C2, E.neg(E.mul(d, C1)))


def eve_attack(E, C2, Pub):
    """Keyless eavesdropper: assumes the paper's K (computable from the public generator).
    Returns (estimated P_m, K*Pub)."""
    KT = E.mul(euler_K(pentatope(E.B[0])), Pub)
    return E.add(C2, E.neg(KT)), KT


def build_real_trace(msg, improved=False):
    E = REAL
    t = {"msg": msg, "improved": improved}
    t["d"] = secrets.randbelow(E.N - 1) + 1
    t["Pub"] = E.mul(t["d"], E.B)
    t["m"], t["tries"], t["Pm"], t["j"] = koblitz_encode(E, msg)
    t["S"] = pentatope(E.B[0])
    t["K_paper"] = euler_K(t["S"])
    t["x_h"], t["S_h"], k = hardened_K(E) if improved else (None, None, None)
    t["K"], t["C1"], t["T"], t["C2"] = encrypt_point(E, t["Pm"], t["Pub"], improved, k)
    t["valid"] = E.valid(t["C1"]) and E.valid(t["C2"])
    t["dC1"] = E.mul(t["d"], t["C1"])
    t["Pm2"] = decrypt_point(E, t["C1"], t["C2"], t["d"], improved)
    t["back"] = koblitz_decode(E, t["Pm2"])
    t["evePm"], t["eveT"] = eve_attack(E, t["C2"], t["Pub"])
    t["eve"] = koblitz_decode(E, t["evePm"])
    return t


# ============================================================================= step texts (plain words + math + values)
def real_steps(t):
    E, imp, msg = REAL, t["improved"], t["msg"]
    hexmsg = " ".join("%02x" % b for b in msg)
    S = []

    def add(title, active, token, plain, math, values, verdict=None):
        S.append(dict(title=title, active=active, token=token, plain=plain, math=math, values=values, verdict=verdict))

    add("Public setup", ["params"], None,
        "Everybody (Alice, Bob and any attacker) agrees on one standard curve and one starting point B. Nothing here is secret.",
        "y^2 = x^3 + a*x + b  (mod p),   a = -3",
        [("p", short(E.p)), ("b", short(E.b)), ("B  (x)", short(E.B[0])), ("B  (y)", short(E.B[1])),
         ("N = order of B", short(E.N))])
    add("Bob creates his key pair", ["keygen"], ("keygen", "enc", "Pub"),
        "Bob picks a random secret number d and publishes the point Pub = d*B. Nobody can get d back from Pub.",
        "d in [1, N-1] random;     Pub = d * B",
        [("d  (%d bit) SECRET" % t["d"].bit_length(), short(t["d"])), ("Pub (published)", fmt_pt(t["Pub"])),
         ("Pub on curve?", str(E.on(t["Pub"])))])
    tr = "; ".join("j=%d %s" % (j, "ok" if ok else "no y") for j, _, ok in t["tries"])
    add("Alice turns her text into a curve point", ["msg", "kob"], ("msg", "kob", "m"),
        "The maths only works on points, so the bytes are hidden inside an x-coordinate (Koblitz): x = 256*m + j. "
        "We try j = 0, 1, 2... until a matching y exists.",
        "m = 0x01 || bytes;   x = 256*m + j;   y = rhs^((p+1)/4)",
        [("message", '"%s"  (%d bytes)' % (msg.decode("utf-8", "replace"), len(msg))), ("bytes", hexmsg),
         ("tries", tr), ("P_m", fmt_pt(t["Pm"])),
         ("look inside x", "0x%x   <- your bytes are readable here" % t["Pm"][0])])
    if imp:
        add("Improved: pentatope K from a secret random x", ["pent"], ("params", "pent", "x"),
            "IMPROVEMENT (deviation from [18]): the pentatope and Euler steps stay, but their input is no longer the public B_x. "
            "Alice draws a new secret random x for every message, so nobody else can compute K.",
            "x in [1, N-1] random;   S = x(x+1)(x+2)(x+3)/24;   K = (S^2 + S + 41) mod N",
            [("x (secret, one-time)", short(t["x_h"])), ("S  (%d bit)" % t["S_h"].bit_length(), short(t["S_h"])),
             ("K mod N (secret)", short(t["K"])),
             ("size", "%d bit  (paper's K: %d bit)" % (t["K"].bit_length(), t["K_paper"].bit_length()))])
    else:
        add("The paper's key K from the pentatope number", ["params", "pent"], ("params", "pent", "B_x"),
            "The paper derives its encryption key from the generator's x-coordinate: S = pentatope number, K = S^2 + S + 41. "
            "Problem: B is public, so K is public too.",
            "S = x(x+1)(x+2)(x+3)/24 with x = B_x;    K = S^2 + S + 41",
            [("S  (%d bit)" % t["S"].bit_length(), short(t["S"])), ("K  (%d bit)" % t["K_paper"].bit_length(), short(t["K_paper"])),
             ("who can compute K?", "EVERYONE (only B is needed)")])
    add("First ciphertext point  C1 = k * B", ["pent", "enc"], ("pent", "enc", "k"),
        "Alice multiplies the starting point B by her key number. In the paper this is the SAME point for every message ever sent."
        if not imp else "With a fresh x (hence a fresh K) this point is different for every message, so ciphertexts cannot be linked.",
        "C1 = K * B",
        [("C1", fmt_pt(t["C1"])),
         ("scalar size", "%d bit -> ~%d point operations" % (t["K"].bit_length(), t["K"].bit_length() + bin(t["K"]).count("1")))])
    add("Second ciphertext point  C2 = Pm + k * Pub", ["kob", "enc"], ("kob", "enc", "Pm"),
        "Alice masks her message point by adding k*Pub (a point only someone who knows k or d can remove).",
        "T = k * Pub;     C2 = P_m + T",
        [("T = k*Pub", fmt_pt(t["T"])), ("C2", fmt_pt(t["C2"]))])
    if imp:
        add("Only (C1, C2) travels - compressed", ["enc", "chan"], ("enc", "chan", "(C1,C2)"),
            "IMPROVEMENT (deviation from the paper's 512-bit points): each point is sent as its x-coordinate plus one byte "
            "saying whether y is even or odd. The receiver recomputes y = sqrt(x^3 + ax + b). 2 x 33 bytes = 528 bit instead "
            "of 1024 bit. Anybody can still record them.",
            "point = 02/03 || x   (33 bytes);   y = rhs^((p+1)/4), parity from the prefix",
            [("C1 sent as", compress_hex(t["C1"])), ("C2 sent as", compress_hex(t["C2"])),
             ("size", "66 bytes = 528 bit for a %d-byte message (paper's format: 128 bytes); one block per started "
                      "29 bytes" % len(msg))])
    else:
        add("Only (C1, C2) travels", ["enc", "chan"], ("enc", "chan", "(C1,C2)"),
            "Two points, 4 x 256 bit = 1024 bit = 128 bytes, go over the open channel. Anybody can record them.",
            "ciphertext = (C1, C2)", [("size", "128 bytes for a %d-byte message (one block; peecc.c uses one block per "
                                               "started 29 bytes)" % len(msg))])
    if imp:
        add("Bob validates and decrypts", ["chan", "dec", "keygen"], ("chan", "dec", "(C1,C2)"),
            "IMPROVEMENT: Bob first checks both points really lie on the curve (rejects forged/off-curve input), then computes C2 - d*C1.",
            "check C1, C2 on curve;   P_m' = C2 - d * C1",
            [("C1, C2 valid?", str(t["valid"])), ("d*C1", fmt_pt(t["dC1"])), ("equals T?", str(t["dC1"] == t["T"])),
             ("P_m'", fmt_pt(t["Pm2"]))])
    else:
        add("Bob decrypts", ["chan", "dec", "keygen"], ("chan", "dec", "(C1,C2)"),
            "Bob uses his secret d: d*C1 = d*k*B = k*(d*B) = k*Pub, which is exactly the mask Alice added, so subtracting it gives P_m back.",
            "P_m' = C2 - d * C1",
            [("d*C1", fmt_pt(t["dC1"])), ("equals T = k*Pub?", str(t["dC1"] == t["T"])), ("P_m'", fmt_pt(t["Pm2"])),
             ("P_m' == P_m ?", str(t["Pm2"] == t["Pm"]))])
    add("Bob turns the point back into text", ["dec", "dko"], ("dec", "dko", "P_m'"),
        "Reverse of Koblitz: m = floor(x / 256); remove the leading 0x01.",
        "m = floor(x / 256)",
        [("x", short(t["Pm2"][0], 20)), ("bytes", " ".join("%02x" % b for b in (t["back"] or b"")))])
    ok = t["back"] == msg
    add("Result", ["dko", "out"], ("dko", "out", "m"),
        "Bob reads exactly what Alice sent.", "decrypt(encrypt(m)) = m",
        [("decoded", '"%s"' % (t["back"] or b"?").decode("utf-8", "replace"))],
        ("good" if ok else "bad", "MATCH - correct decryption" if ok else "MISMATCH"))
    ev = t["eve"] == msg
    add("Attacker Eve - without Bob's key", ["chan", "eve", "pent"], ("chan", "eve", "(C1,C2)"),
        "Eve copies (C1, C2) from the channel. She knows Pub and, in the paper's scheme, also K. So she subtracts K*Pub herself.",
        "P_m = C2 - K * Pub     (K computed from B_x, no secret used)",
        [("Eve's K*Pub", fmt_pt(t["eveT"])),
         ("Eve reads", ('"%s"' % t["eve"].decode("utf-8", "replace")) if ev else "garbage - decoding fails")],
        ("bad", 'ATTACK SUCCEEDS: Eve read "%s" without any private key. Base-paper PEECC is not confidential.'
         % t["eve"].decode("utf-8", "replace")) if ev else
        ("good", "ATTACK FAILS: K now comes from a one-time secret x, not from the public B_x."))
    return S


# ============================================================================= toy curve
def make_toy():
    p, a, b = 23, 1, 1
    pts = [(x, y) for x in range(p) for y in range(p) if (y * y - (x ** 3 + a * x + b)) % p == 0]
    probe = Curve(p, a, b, None, 0)

    def order(P):
        k, R = 1, P
        while R is not None:
            R, k = probe.add(R, P), k + 1
        return k
    B = (18, 3) if (18, 3) in pts and order((18, 3)) == order(max(pts, key=order)) else max(pts, key=order)
    return Curve(p, a, b, B, order(B)), pts


def toy_valid_messages(E, kappa=2):
    return [m for m in range(1, 12) if koblitz_encode(E, m, kappa)[2] is not None]


def toy_multiples(E):
    """Dictionary point -> k such that point = k*B."""
    out, R = {}, None
    for k in range(1, E.N):
        R = E.add(R, E.B)
        out[R] = k
    return out


def double_and_add_rows(d):
    """Trace of double-and-add for d*B: list of (bit, value after doubling, value after add)."""
    rows, acc = [], 0
    for bit in bin(d)[2:]:
        acc *= 2
        dbl = acc
        if bit == "1":
            acc += 1
        rows.append((bit, dbl, acc))
    return rows


def build_toy_frames(E, pts, d, m, improved, r, kappa=2):
    B, N = E.B, E.N
    Pub = E.mul(d, B)
    _, tries, Pm, j = koblitz_encode(E, m, kappa)
    S = pentatope(B[0]); Kp = euler_K(S)
    xh, Sh, k = hardened_K(E, r) if improved else (None, None, Kp)
    C1, T = E.mul(k, B), E.mul(k, Pub)
    C2 = E.add(Pm, T)
    dC1 = E.mul(d, C1)
    Pm2 = E.add(C2, E.neg(dC1))
    eve = E.add(C2, E.neg(E.mul(Kp, Pub)))
    mult = toy_multiples(E)
    chain = [E.mul(i, B) for i in range(1, d + 1)]
    rows = double_and_add_rows(d)
    F = []
    F.append(dict(title="The curve and its points",
                  plain="All dots are the only points of this tiny curve. Starting from B and adding B again and again visits every dot "
                        "(B, 2B, 3B, ...). Tick 'label every dot' to see which dot is which multiple.",
                  math="y^2 = x^3 + x + 1 (mod 23);   B = %s;   order N = %d" % (B, N),
                  marks={"B": B}, chain=[], arrows=[]))
    F.append(dict(title="Public key  Pub = d * B",
                  plain="Bob's secret d = %d means: add B to itself %d times. The orange path shows B, 2B, 3B, ... up to Pub. "
                        "Going backwards (finding d from Pub) is the hard problem." % (d, d),
                  math="Pub = %d*B = %s\ndouble-and-add of d = %s:\n%s" % (d, Pub, bin(d)[2:], "  ".join(
                      "[bit %s: x2=%d%s]" % (b_, dbl, ("+1=%d" % ad) if b_ == "1" else "") for b_, dbl, ad in rows)),
                  marks={"B": B, "Pub": Pub}, chain=chain, arrows=[]))
    F.append(dict(title="Message m becomes a point P_m",
                  plain="m = %d is put into the x-coordinate (x = %d*m + j). The first j that gives a valid y wins." % (m, kappa),
                  math="tries: %s\nP_m = %s" % (", ".join("j=%d -> x=%d %s" % (jj, x, "ok" if ok else "no y") for jj, x, ok in tries), Pm),
                  marks={"B": B, "Pub": Pub, "Pm": Pm}, chain=[], arrows=[]))
    if improved:
        F.append(dict(title="Improved: K from a one-time random x",
                      plain="The pentatope step stays, but its input is a fresh secret x (here x = %d) instead of the public B_x. "
                            "A different x next time gives a different K and a different ciphertext." % xh,
                      math="S = %d*%d*%d*%d/24 = %d;   K = (S^2+S+41) mod N = %d   (the paper's K mod N would be %d)"
                           % (xh, xh + 1, xh + 2, xh + 3, Sh, k, Kp % N),
                      marks={"B": B, "Pub": Pub, "Pm": Pm}, chain=[], arrows=[]))
    else:
        F.append(dict(title="The paper's key K",
                      plain="S comes from B's x-coordinate (%d) and K = S^2+S+41. Because B is public, anyone can compute this K." % B[0],
                      math="S = %d*%d*%d*%d/24 = %d;   K = %d;   K mod N = %d" % (B[0], B[0] + 1, B[0] + 2, B[0] + 3, S, Kp, Kp % N),
                      marks={"B": B, "Pub": Pub, "Pm": Pm}, chain=[], arrows=[]))
    F.append(dict(title="C1 = k * B",
                  plain="Alice sends the first point C1 = K*B (K %s)." % ("from the secret x" if improved else "from B_x, the same every time"),
                  math="C1 = %d*B = %s   (the dot labelled %d)" % (k, C1, mult.get(C1, 0)),
                  marks={"B": B, "Pub": Pub, "Pm": Pm, "C1": C1}, chain=[], arrows=[]))
    F.append(dict(title="C2 = P_m + k * Pub",
                  plain="She computes the mask T = k*Pub and adds it to the message point. The arrow shows the jump from P_m to C2.",
                  math="T = %s;   C2 = %s + %s = %s" % (T, Pm, T, C2),
                  marks={"Pm": Pm, "T": T, "C2": C2, "C1": C1}, chain=[], arrows=[(Pm, C2)]))
    F.append(dict(title="Bob decrypts: C2 - d * C1",
                  plain="Bob computes d*C1, which equals the mask T, and subtracts it. The arrow goes from C2 back to P_m.",
                  math="d*C1 = %s  (== T: %s);\nC2 - d*C1 = %s  (== P_m: %s)" % (dC1, dC1 == T, Pm2, Pm2 == Pm),
                  marks={"C1": C1, "dC1": dC1, "C2": C2, "Pm'": Pm2}, chain=[], arrows=[(C2, Pm2)]))
    ok = eve == Pm
    F.append(dict(title="Eve without a key",
                  plain=("Eve knows B, Pub, (C1, C2), and the paper's K. She computes C2 - K*Pub and gets the message point: "
                         "ATTACK SUCCEEDS." if ok else
                         "Eve assumes the paper's K, but Alice's K came from a secret x, so C2 - K*Pub is just another point: ATTACK FAILS "
                         "(in a toy group she can be lucky when both K values happen to agree mod N)."),
                  math="Eve: C2 - K*Pub = %s;   P_m = %s;   equal: %s" % (eve, Pm, ok),
                  marks={"Pub": Pub, "C2": C2, "Pm": Pm, "Eve": eve}, chain=[], arrows=[(C2, eve)], good=not ok))
    return F


# ============================================================================= benchmark (live, Python implementation)
def bench_trial(E, improved, rng_bytes):
    """One trial: encrypt a random message, time it, and let the keyless Eve try."""
    d = secrets.randbelow(E.N - 1) + 1
    Pub = E.mul(d, E.B)
    _, _, Pm, _ = koblitz_encode(E, rng_bytes)
    t0 = time.perf_counter()
    k, C1, T, C2 = encrypt_point(E, Pm, Pub, improved)
    dt = (time.perf_counter() - t0) * 1000
    evePm, _ = eve_attack(E, C2, Pub)
    dec = decrypt_point(E, C1, C2, d, improved)
    _, C1b, _, C2b = encrypt_point(E, Pm, Pub, improved)          # same message, same key, second time
    return dict(ms=dt, scalar_bits=k.bit_length(), c1=C1, eve=koblitz_decode(E, evePm) == rng_bytes,
                ok=koblitz_decode(E, dec) == rng_bytes, same=(C1 == C1b and C2 == C2b))


# ============================================================================= performance metrics (measured / counted)
def mean_sd(xs):
    import math
    n = len(xs); mu = sum(xs) / n
    return mu, math.sqrt(sum((x - mu) ** 2 for x in xs) / max(1, n - 1))


def metrics_trial(E, improved, msg):
    """One trial of every per-operation metric for one scheme. Counters are read from the Curve object."""
    def snap():
        return E.n_mul, E.n_dbl, E.n_add

    def delta(a, b):
        return tuple(y - x for x, y in zip(a, b))

    d = secrets.randbelow(E.N - 1) + 1
    s0, t0 = snap(), time.perf_counter()
    Pub = E.mul(d, E.B)
    t_key, c_key = (time.perf_counter() - t0) * 1000, delta(s0, snap())
    Pm = koblitz_encode(E, msg)[2]
    s0, t0 = snap(), time.perf_counter()
    k, C1, T, C2 = encrypt_point(E, Pm, Pub, improved)
    t_enc, c_enc = (time.perf_counter() - t0) * 1000, delta(s0, snap())
    s0, t0 = snap(), time.perf_counter()
    dec = decrypt_point(E, C1, C2, d, improved)
    t_dec, c_dec = (time.perf_counter() - t0) * 1000, delta(s0, snap())
    _, C1b, _, C2b = encrypt_point(E, Pm, Pub, improved)
    evePm, _ = eve_attack(E, C2, Pub)
    return dict(t_key=t_key, t_enc=t_enc, t_dec=t_dec, c_key=c_key, c_enc=c_enc, c_dec=c_dec, plain=len(msg),
                unique=(C1, C2) != (C1b, C2b), eve=koblitz_decode(E, evePm) == msg, ok=koblitz_decode(E, dec) == msg)


def metrics_table(E, res):
    """Rows: (metric, unit, paper-exact, improved, how obtained)."""
    n = len(res[False])

    def ms(key, m):
        mu, sd = mean_sd([r[key] for r in res[m]])
        return "%.1f +- %.1f" % (mu, sd)

    def cnt(key, idx, m):
        return "%d" % round(sum(r[key][idx] for r in res[m]) / n)

    def mul_dbl_add(key, m):
        return "%s / %s / %s" % (cnt(key, 0, m), cnt(key, 1, m), cnt(key, 2, m))

    def inv(key, m):
        return "%d" % round(sum(r[key][1] + r[key][2] for r in res[m]) / n)

    def thr(m):
        return "%.0f" % (sum(r["plain"] / (r["t_enc"] / 1000) for r in res[m]) / n)

    pl = res[False][0]["plain"]
    return [
        ("Key generation time", "ms", ms("t_key", False), ms("t_key", True), "measured (Python)"),
        ("Encryption time", "ms", ms("t_enc", False), ms("t_enc", True), "measured (Python)"),
        ("Decryption time", "ms", ms("t_dec", False), ms("t_dec", True), "measured (Python)"),
        ("Encryption throughput (%d-byte message)" % pl, "bytes/s", thr(False), thr(True), "derived from time"),
        ("Scalar mult. / doublings / additions: keygen", "count", mul_dbl_add("c_key", False), mul_dbl_add("c_key", True), "counted"),
        ("Scalar mult. / doublings / additions: encrypt", "count", mul_dbl_add("c_enc", False), mul_dbl_add("c_enc", True), "counted"),
        ("Scalar mult. / doublings / additions: decrypt", "count", mul_dbl_add("c_dec", False), mul_dbl_add("c_dec", True), "counted"),
        ("Field inversions per encryption (affine: 1 per point op)", "count", inv("c_enc", False), inv("c_enc", True), "counted"),
        ("Private key size", "bit", "256", "256", "fixed by curve"),
        ("Public key size (x and y)", "bit", "512", "512", "fixed by curve"),
        ("Ciphertext size per block (C1 and C2)", "bit", "1024", "528", "512-bit vs compressed points"),
        ("Ciphertext expansion (%d-byte message)" % pl, "x", "%.1f" % (1024 / (8 * pl)), "%.1f" % (528 / (8 * pl)), "derived"),
        ("Same message + key encrypted twice: distinct ciphertexts", "of %d" % n,
         "%d" % sum(r["unique"] for r in res[False]), "%d" % sum(r["unique"] for r in res[True]), "measured"),
        ("Keyless eavesdropper recovers the message", "%", "%.0f" % (100.0 * sum(r["eve"] for r in res[False]) / n),
         "%.0f" % (100.0 * sum(r["eve"] for r in res[True]) / n), "measured"),
        ("Decryption correct", "of %d" % n, "%d" % sum(r["ok"] for r in res[False]), "%d" % sum(r["ok"] for r in res[True]), "measured"),
        ("ECDLP security level of the curve (Pollard rho)", "bit", "%d" % (E.N.bit_length() // 2), "%d" % (E.N.bit_length() // 2),
         "theory: sqrt(N)"),
    ]


# Earlier C measurement (docs/thesis, Table 8), shown only when peecc.dll is not built
C_REF = {"encrypt_ms": 14.626, "mul_2029_ms": 6.983, "mul_256_ms": 0.836}


def c_bench():
    """Measured C timings (ms) of keygen, encrypt and decrypt of one block for both modes via peecc_bench in
    peecc.dll / libpeecc.so ({False: paper-exact, True: hardened}), or None if the library is not built."""
    try:
        import protocol as P
        lib = P.Peecc()
    except (OSError, ImportError):
        return None
    return {False: lib.bench(10, P.mode_of(False)), True: lib.bench(50, P.mode_of(True))}


# ============================================================================= self-test
def selftest():
    E = REAL
    assert E.on(E.B) and E.mul(E.N, E.B) is None
    assert E.mul(2, E.B)[0] == 0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978
    for imp in (False, True):
        for text in (b"hello world", b"", b"A" * 29):
            t = build_real_trace(text, imp)
            assert t["back"] == text, "round trip"
            assert (t["eve"] == text) == (not imp), "eavesdropper outcome"
            assert len(real_steps(t)) == 11
    t = build_real_trace(b"hello world")
    assert t["C1"][0] == 0x681dc23639d030c4df03de37d6459fc1c8bde47e06c619c2c40d16c043c19f4f, "C1 matches peecc.exe"
    assert t["Pm"][0] == 0x168656c6c6f20776f726c6401, "Pm matches peecc.exe"
    ti = build_real_trace(b"hello world", True)
    bad = (ti["C1"][0], (ti["C1"][1] + 1) % E.p)
    assert decrypt_point(E, bad, ti["C2"], ti["d"], True) is None, "off-curve point rejected"
    r1, r2 = bench_trial(E, True, b"abc"), bench_trial(E, False, b"abc")
    assert r1["ok"] and r2["ok"] and r2["eve"] and not r1["eve"] and not r1["same"] and r2["same"]
    assert r1["scalar_bits"] <= 256 and r2["scalar_bits"] == 2029
    E.n_mul = E.n_dbl = E.n_add = 0
    mt = [metrics_trial(E, False, b"hello world"), metrics_trial(E, True, b"hello world")]
    assert mt[0]["c_enc"][0] == 2 and mt[1]["c_enc"][0] == 2 and mt[0]["c_dec"][0] == 1, "scalar multiplication counts"
    assert mt[0]["c_enc"][1] == 2 * 2028 and mt[0]["c_enc"][2] > 1000 and mt[1]["c_enc"][1] <= 2 * 255, "doubling counts"
    assert not mt[0]["unique"] and mt[1]["unique"] and mt[0]["eve"] and not mt[1]["eve"]
    assert E.mul(euler_K(pentatope(E.B[0])), E.B) == E.mul(euler_K(pentatope(E.B[0])) % E.N, E.B), "K mod N shortcut"
    EM = make_math_curve()
    assert EM.mul(EM.N, EM.B) is None and EM.mul(2, EM.B) == (12, 4) and EM.mul(3, EM.B) == (9, 7)
    for mm in toy_valid_messages(EM):
        for dd in range(1, EM.N):
            for imp, rr in ((False, 10), (True, 10), (True, 1), (True, 27)):
                steps = build_math_steps(EM, dd, mm, imp, rr)
                assert len(steps) == 10 and all(st["trace"] for st in steps)
    ex = build_math_steps(EM, 3, 3, True, 10)       # worked example: d = 3, m = 3, improved with x = 10
    kx = hardened_K(EM, 10)[2]
    assert kx == euler_K(pentatope(10)) % EM.N == 1
    Pm3 = koblitz_encode(EM, 3, 2)[2]
    assert fmt(EM.add(Pm3, EM.mul(kx, EM.mul(3, EM.B)))) in " ".join(ex[5]["trace"]), "C2 = P_m + K*Pub"
    assert {euler_K(pentatope(x_)) % EM.N for x_ in range(1, EM.N)} == {1, 13, 15, 27}   # tiny group: only 4 K values
    assert "MATCH" in " ".join(ex[8]["trace"]) and ex[9]["good"]
    assert not build_math_steps(EM, 3, 3, False, 10)[9]["good"]
    T, pts = make_toy()
    msgs = toy_valid_messages(T)
    assert msgs and T.mul(T.N, T.B) is None
    for imp in (False, True):
        for m in msgs:
            for d in range(1, T.N):
                assert len(build_toy_frames(T, pts, d, m, imp, 5)) == 8
    try:                                               # protocol tab (needs peecc.dll / libpeecc.so: make lib)
        for hard in (False, True):
            ev, sm = build_protocol_events(hard)
            assert sm["ok"] and sm["messages"] == 12 and sm["sessions"] == 8
            assert sm["wire_bits"] == (8448 if hard else 16384), "compressed points halve the ciphertext"
            assert sm["eve_read"] == (0 if hard else 12), "eavesdropper on M1-M12"
            assert all(e["plain"] is not None for e in ev if e["kind"] == "message")
        ev, sm = build_protocol_events(True, 1)
        assert sm["ok"] and any(e["kind"] == "fallback" and e["dst"] == "B2" for e in ev)
        proto = ", protocol tab"
    except OSError:
        proto = " (protocol tab skipped: build peecc.dll with make lib)"
    print("selftest OK: matches peecc.exe, round trips, eavesdropper (paper-exact breaks / improved blocks), validation, "
          "toy frames" + proto)



# ============================================================================= math walkthrough (toy curve, every number shown)
def fmt(P):
    return "O" if P is None else "(%d, %d)" % P


def trace_add(E, P, Q, pn="P", qn="Q"):
    """Point addition with every intermediate number written out. Returns (result, lines)."""
    p = E.p
    if P is None:
        return Q, ["%s is O (the identity), so %s + %s = %s" % (pn, pn, qn, fmt(Q))]
    if Q is None:
        return P, ["%s is O (the identity), so %s + %s = %s" % (qn, pn, qn, fmt(P))]
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None, ["same x and opposite y: %s + %s = O (point at infinity)" % (pn, qn)]
    if P == Q:
        num, den = 3 * x1 * x1 + E.a, 2 * y1
        L = ["doubling:  lambda = (3*x1^2 + a) / (2*y1) = (3*%d^2 + %d) / (2*%d) = %d / %d   (mod %d)" % (x1, E.a, y1, num, den, p)]
    else:
        num, den = y2 - y1, x2 - x1
        L = ["lambda = (y2 - y1) / (x2 - x1) = (%d - %d) / (%d - %d) = %d / %d   (mod %d)" % (y2, y1, x2, x1, num, den, p)]
    nm, dm = num % p, den % p
    inv = pow(dm, -1, p)
    lam = nm * inv % p
    L.append("   %d / %d = %d * %d^-1 = %d * %d = %d     (because %d * %d = %d = 1 mod %d)" % (nm, dm, nm, dm, nm, inv, lam, dm, inv, dm * inv, p))
    x3 = (lam * lam - x1 - x2) % p
    L.append("x3 = lambda^2 - x1 - x2 = %d^2 - %d - %d = %d   (mod %d)" % (lam, x1, x2, x3, p))
    y3 = (lam * (x1 - x3) - y1) % p
    L.append("y3 = lambda*(x1 - x3) - y1 = %d*(%d - %d) - %d = %d   (mod %d)" % (lam, x1, x3, y1, y3, p))
    R = (x3, y3)
    assert R == E.add(P, Q)
    L.append("=> %s + %s = %s" % (pn, qn, fmt(R)))
    return R, L


def trace_mul(E, k, P, name="B"):
    """Double-and-add with every step shown. Returns (result, lines)."""
    kb = bin(k)[2:]
    L = ["k = %d = %s (binary). Double-and-add, leftmost bit first:" % (k, kb)]
    R, t = None, 0
    for bit in kb:
        R = E.add(R, R); t *= 2
        line = "  bit %s: double -> %d*%s = %s" % (bit, t, name, fmt(R))
        if bit == "1":
            R = E.add(R, P); t += 1
            line += ";  add %s -> %d*%s = %s" % (name, t, name, fmt(R))
        L.append(line)
    assert R == E.mul(k, P)
    L.append("=> %d*%s = %s" % (k, name, fmt(R)))
    return R, L


def make_math_curve():
    """Curve used by the walkthrough: y^2 = x^3 + x + 1 (mod 23), generator B = (18, 3) of order 28."""
    return Curve(23, 1, 1, (18, 3), 28)


def build_math_steps(E, d, m, improved, r, kappa=2):
    """Node-by-node walkthrough: each step has node, inputs, operation, outputs, words, maths, trace lines, plot marks."""
    p, N, B = E.p, E.N, E.B
    mult = toy_multiples(E)
    x = B[0]
    S = pentatope(x); K = euler_K(S)
    xh, Sh, kh = hardened_K(E, r) if improved else (None, None, None)
    k = (kh if improved else K)
    kk = k % N
    St = []

    def step(title, node, inputs, op, outputs, words, maths, trace, marks, chain=(), arrows=()):
        St.append(dict(title=title, node=node, inputs=inputs, op=op, outputs=outputs, words=words, maths=maths,
                       trace=trace, marks=marks, chain=list(chain), arrows=list(arrows)))

    step("Public setup", "Everyone", ["curve parameters"], "agree on curve, B and N", ["p, a, b, B, N"],
         "All parties agree on one curve and one starting point B. Adding B to itself again and again visits every point of the "
         "group; after N additions we are back at the start (the point at infinity O). Nothing here is secret.",
         ["y^2 = x^3 + a*x + b  (mod p)", "N * B = O"],
         ["p = %d, a = %d, b = %d" % (p, E.a, E.b), "B = %s,  group order N = %d  (N*B = O)" % (fmt(B), N),
          "%d points on the curve; every dot below is one multiple k*B" % len(mult)],
         {"B": B})
    Pub = E.mul(d, B)
    _, tl = trace_mul(E, d, B, "B")
    step("Key generation", "Bob", ["d (secret)", "B"], "Pub = d * B", ["Pub (public)"],
         "Bob chooses a secret number d. He publishes the point Pub = d*B, i.e. B added to itself d times. "
         "Going backwards, finding d from Pub, is the elliptic-curve discrete-logarithm problem.",
         ["d in [1, N-1]", "Pub = d * B"],
         ["d = %d  (Bob keeps this secret)" % d] + tl + ["Pub = %s is published" % fmt(Pub)],
         {"B": B, "Pub": Pub}, chain=[E.mul(i, B) for i in range(1, d + 1)])
    _, tries, Pm, j = koblitz_encode(E, m, kappa)
    L = ["message number m = %d;  try x = %d*m + j:" % (m, kappa)]
    for jj, xx, ok in tries:
        rhs = (xx ** 3 + E.a * xx + E.b) % p
        y = pow(rhs, (p + 1) // 4, p)
        L.append("  j=%d: x=%d, rhs = x^3 + x + 1 = %d (mod %d);  y = rhs^((p+1)/4) = %d^%d = %d;  y^2 = %d  -> %s"
                 % (jj, xx, rhs, p, rhs, (p + 1) // 4, y, y * y % p, "equals rhs: point found" if ok else "differs: no square root, try next j"))
    L.append("P_m = %s" % fmt(Pm))
    step("Message to a curve point (Koblitz)", "Alice", ["message m", "curve"], "m -> P_m = (x, y)", ["P_m"],
         "The curve arithmetic works on points, not numbers. Alice hides her message number in the x-coordinate (x = 2m + j) and "
         "tries j = 0, 1, ... until x^3 + x + 1 has a square root y modulo p. The real program uses 256*m + j and a marker byte.",
         ["x = kappa*m + j", "y = rhs^((p+1)/4) mod p   (works because p = 3 mod 4)"], L,
         {"B": B, "Pub": Pub, "Pm": Pm})
    if improved:
        Kh = euler_K(Sh)
        L = ["x = %d is drawn at random from [1, N-1] (one-time secret, new for every message)%s"
             % (xh, "" if xh == r else "  (x = %d gave K = 0 mod N, so the next x is used)" % r),
             "S = x(x+1)(x+2)(x+3)/24 = %d*%d*%d*%d/24 = %d" % (xh, xh + 1, xh + 2, xh + 3, Sh),
             "K = S^2 + S + 41 = %d^2 + %d + 41 = %d;   K mod %d = %d" % (Sh, Sh, Kh, N, kk),
             "x is NOT the public B_x, so nobody else can compute this K",
             "(for comparison, the paper uses x = B_x = %d: K = %d, K mod N = %d)" % (x, K, K % N)]
        step("The key K from a one-time random x", "Alice", ["random source"], "x random;  S, K from x", ["K (secret)"],
             "Improvement: the pentatope number and Euler's polynomial stay, but their input is a fresh secret x instead of the "
             "public generator coordinate. Anybody can compute the paper's K, nobody can compute this one.",
             ["x in [1, N-1], fresh per message", "S = x(x+1)(x+2)(x+3)/24", "K = (S^2 + S + 41) mod N"], L,
             {"B": B, "Pub": Pub, "Pm": Pm})
    else:
        L = ["x = B_x = %d" % x, "S = x(x+1)(x+2)(x+3)/24 = %d*%d*%d*%d/24 = %d" % (x, x + 1, x + 2, x + 3, S),
             "K = S^2 + S + 41 = %d^2 + %d + 41 = %d" % (S, S, K),
             "Because N*B = O only K mod N matters: K mod %d = %d,  so K*Q = %d*Q for every point Q in the group" % (N, kk, kk),
             "Everything above uses only public data (B), so anybody can compute K"]
        step("The paper's key K (pentatope number)", "Alice", ["B_x (public)"], "S, K from B_x", ["K (public!)"],
             "The base paper does not use a random number. It computes K from the generator's x-coordinate with the pentatope number S "
             "and Euler's polynomial. Since B is public, K is public.",
             ["S = x(x+1)(x+2)(x+3)/24", "K = S^2 + S + 41"], L, {"B": B, "Pub": Pub, "Pm": Pm})
    C1, tl = trace_mul(E, kk, B, "B")
    step("First ciphertext point  C1 = k * B", "Alice", ["k", "B"], "C1 = k * B", ["C1"],
         "Alice multiplies the starting point by k. C1 hides k (discrete-log problem), yet it lets Bob cancel the mask later.",
         ["C1 = k * B"], ["k = K mod N = %d (%s)" % (kk, "K from the secret x" if improved else "K from the public B_x")] + tl,
         {"B": B, "Pub": Pub, "Pm": Pm, "C1": C1})
    T, tl1 = trace_mul(E, kk, Pub, "Pub")
    C2, tl2 = trace_add(E, Pm, T, "P_m", "T")
    step("Second ciphertext point  C2 = P_m + k * Pub", "Alice", ["P_m", "k", "Pub"], "T = k*Pub;  C2 = P_m + T", ["C2"],
         "Alice computes the mask T = k*Pub (only someone knowing k or d can compute it) and adds it to the message point. "
         "The result C2 looks unrelated to P_m.",
         ["T = k * Pub", "C2 = P_m + T"], ["Mask T:"] + tl1 + ["", "Add the message point:"] + tl2,
         {"Pm": Pm, "T": T, "C2": C2, "C1": C1}, arrows=[(Pm, C2)])
    step("Transmission", "Channel", ["C1", "C2"], "send (C1, C2)", ["(C1, C2) seen by everyone"],
         "Only two points travel. Anyone can read them, together with the public key Pub and the public curve data.",
         ["ciphertext = (C1, C2)"], ["C1 = %s" % fmt(C1), "C2 = %s" % fmt(C2), "Pub = %s" % fmt(Pub),
                                      "private key d, one-time number k and message point P_m are NOT sent"],
         {"C1": C1, "C2": C2, "Pub": Pub})
    dC1, tl1 = trace_mul(E, d % N, C1, "C1")
    negT = E.neg(dC1)
    Pm2, tl2 = trace_add(E, C2, negT, "C2", "(-d*C1)")
    step("Decryption", "Bob", ["C1, C2", "d (secret)"], "P_m = C2 - d*C1", ["P_m"],
         "Bob multiplies C1 by his secret d. Because d*(k*B) = k*(d*B) = k*Pub, he gets exactly the mask T that Alice added, "
         "and subtracting it returns P_m. Bob never needs k.",
         ["d*C1 = d*k*B = k*Pub = T", "P_m = C2 - d*C1"],
         ["d*C1:"] + tl1 + ["d*C1 equals T = %s : %s" % (fmt(T), dC1 == T), "", "negate: -d*C1 = (x, -y) = %s" % fmt(negT), "then add:"] + tl2,
         {"C1": C1, "dC1": dC1, "C2": C2, "Pm'": Pm2}, arrows=[(C2, Pm2)])
    back = None if Pm2 is None else Pm2[0] // kappa
    step("Back to the message", "Bob", ["P_m'"], "m = floor(x / kappa)", ["message m"],
         "Reverse of the encoding: drop j by integer division.",
         ["m = floor(x / kappa)"], ["P_m' = %s,  x = %d" % (fmt(Pm2), Pm2[0]), "m = floor(%d / %d) = %d" % (Pm2[0], kappa, back),
                                    "original message m = %d  ->  %s" % (m, "MATCH" if back == m else "MISMATCH")],
         {"Pm'": Pm2})
    Kp = euler_K(pentatope(x)) % N
    eveT, tl1 = trace_mul(E, Kp, Pub, "Pub")
    eve, tl2 = trace_add(E, C2, E.neg(eveT), "C2", "(-K*Pub)")
    ok = eve == Pm
    step("Attacker Eve (no private key)", "Eve", ["C1, C2, Pub", "B_x"], "C2 - K*Pub with K from B_x", ["guess of P_m"],
         "Eve knows everything on the channel. She computes the paper's K from the public generator and subtracts K*Pub. "
         + ("This equals the real mask, so she recovers the message: the paper's scheme is not confidential."
            if ok else "The real mask used a K from the secret x, not from B_x, so she gets a wrong point: the message stays hidden."),
         ["Eve: P_m = C2 - K*Pub   (K = %d computed from B_x)" % K], ["K mod N = %d" % Kp, "K*Pub:"] + tl1 + ["", "C2 - K*Pub:"] + tl2 +
         ["", "true P_m = %s  ->  Eve %s" % (fmt(Pm), "SUCCEEDS (message exposed)" if ok else "FAILS (message safe)")],
         {"Pub": Pub, "C2": C2, "Pm": Pm, "Eve": eve}, arrows=[(C2, eve)])
    St[-1]["good"] = not ok
    return St


# ============================================================================= results tab (figures written by simulate.py)
RESULT_FIGS = (("claims_scorecard", "Claims scorecard (measured / claimed)"),
               ("improvement_security", "Improvement: security (attacks, eavesdropper)"),
               ("improvement_cost", "Improvement: cost (K size, point ops, time)"),
               ("performance_entities", "Performance: operations and energy per entity"),
               ("performance_latency", "Performance: latency per hop, fallback"),
               ("communication_cost", "Communication cost (model vs on the wire)"),
               ("latency", "Latency vs depth and node count"),
               ("scyther_claims", "Scyther claims (Fig. 6)"))


def claim_figures(claim):
    """The figures that show the evidence for one row of the claims table."""
    c = claim.lower()
    if "communication" in c or "transmission" in c or "reduction" in c:
        return ["communication_cost", "claims_scorecard"]
    if "computation" in c:
        return ["improvement_cost", "performance_entities"]
    if "energy" in c:
        return ["performance_entities"]
    if "re-auth" in c:
        return ["performance_latency"]
    if "attack" in c:
        return ["improvement_security"]
    if "scyther" in c:
        return ["scyther_claims"]
    if "depth" in c:
        return ["latency"]
    return ["claims_scorecard"]


# ============================================================================= protocol tab (protocol.py + peecc.dll)
PROTO_SCENARIOS = ("Normal authentication S1 -> BS", "Buoy B1 unresponsive (fallback to B2)",
                   "Satellite SAT1 answers 4 s late (fallback to SAT2)")


def build_protocol_events(hardened, scenario=0, seed=1):
    """Run IoT Sec. IV-C over the Fig. 1 path of S1 with the real C library and return (events, summary).
    Each message event also carries what the receiver decrypts and what a keyless eavesdropper reads."""
    import random
    import protocol as P
    import simulate as SIM
    lib = P.Peecc()
    net = SIM.new_network(lib, hardened, seed)
    if scenario == 1:
        net.nodes["B1"].alive = False
    elif scenario == 2:
        net.nodes["SAT1"].respond_delay = 4.0
    ev = []
    net.trace = lambda kind, e: ev.append(dict(e, kind=kind))
    t0 = net.clock.now
    res = SIM.run_chain(net, ["S1"], random.Random(seed))
    net.trace = None
    wire = model = 0
    for e in ev:
        if e["kind"] != "message":
            continue
        pkt = e["pkt"]
        dst = net.nodes[pkt.dst]
        e["plain"] = lib.decrypt(pkt.ct, dst.PK, net.mode)
        e["eve"] = lib.eavesdrop(pkt.ct, dst.PU, net.mode)
        e["model_bits"] = SIM.model_bits(dict(label=pkt.label, fields=pkt.fields))
        wire += 8 * len(pkt.ct); model += e["model_bits"]
    summary = dict(ok=all(ok for ok, _ in res.values()), seconds=net.clock.now - t0, wire_bits=wire, model_bits=model,
                   sessions=net.sessions_created, eve_read=sum(1 for e in ev if e["kind"] == "message" and e["eve"] is not None),
                   messages=sum(1 for e in ev if e["kind"] == "message"),
                   kinds={n: net.nodes[n].kind for n in net.nodes})
    return ev, summary


def draw_toy(ax, E, pts, mult, fr, labels=True, dot=150, font=7, ring=430):
    """Toy-curve picture: dots with their k inside, orange chain, blue arrows, one ring + callout per highlighted point."""
    ax.clear()
    ax.set_xlim(-1.5, E.p + 0.5); ax.set_ylim(-1.5, E.p + 0.5); ax.set_aspect("equal")
    ax.set_xticks(range(0, E.p, 2)); ax.set_yticks(range(0, E.p, 2)); ax.grid(alpha=0.18)
    ax.set_facecolor("#FAFBFC")
    for sp in ax.spines.values():
        sp.set_color("#C9D2DA")
    ch = fr["chain"]
    chain_set = set(ch)
    rest = [q for q in pts if q not in chain_set]
    ax.scatter([q[0] for q in rest], [q[1] for q in rest], s=dot, c="#D5DDE5", zorder=2, edgecolors="white")
    if len(ch) > 1:
        ax.plot([c[0] for c in ch], [c[1] for c in ch], "-", c=C["orange"], lw=1.2, alpha=0.7, zorder=3)
    if ch:
        ax.scatter([c[0] for c in ch], [c[1] for c in ch], s=dot, c=C["lorange"], edgecolors=C["orange"], linewidths=1.6, zorder=4)
    if labels:
        for q, k in mult.items():
            ax.text(q[0], q[1], str(k), ha="center", va="center", fontsize=font, color="#2C3640", fontweight="bold", zorder=5)
    for a_, b_ in fr["arrows"]:
        if a_ and b_ and a_ != b_:
            ax.annotate("", xy=b_, xytext=a_, arrowprops=dict(arrowstyle="-|>", color=C["blue"], lw=2.0, shrinkA=9, shrinkB=9), zorder=5)
    groups = {}
    for lab, q in fr["marks"].items():
        if q is not None:
            groups.setdefault(q, []).append(lab)
    cols = [C["blue"], C["orange"], C["green"], C["red"], "#8E44AD", "#16A085", "#7F8C8D"]
    offs = [(26, 24), (-26, 24), (26, -24), (-26, -24), (0, 34), (0, -34)]
    for n, (q, labs) in enumerate(groups.items()):
        col = cols[n % len(cols)]
        ax.scatter([q[0]], [q[1]], s=ring, facecolors="none", edgecolors=col, linewidths=2.6, zorder=6)
        ax.annotate(" = ".join(labs), q, xytext=offs[n % len(offs)], textcoords="offset points", fontsize=9, color=col,
                    fontweight="bold", zorder=8, ha="center", va="center",
                    bbox=dict(boxstyle="round,pad=0.25", fc="white", ec=col, lw=1.2),
                    arrowprops=dict(arrowstyle="-", color=col, lw=1.2, shrinkA=0, shrinkB=11))


# ============================================================================= GUI
C = dict(navy="#12263F", blue="#2F6FB0", lblue="#DCE9F7", green="#2E8B57", lgreen="#DDF0E3", orange="#E67E22",
         lorange="#FCE8D5", red="#B22222", lred="#F8DADA", grey="#EEF1F4", dgrey="#5B6770", yellow="#FFF6D6", white="#FFFFFF")
NODES = {   # id: (cx, cy, title, body, fill)
    "msg": (95, 78, "Plaintext", "message m", C["grey"]),
    "kob": (295, 78, "Koblitz encode", "m -> point Pm", C["lblue"]),
    "enc": (745, 78, "PEECC encrypt", "C1 = k*B\nC2 = Pm + k*Pub", C["lgreen"]),
    "params": (295, 160, "Public parameters", "p, a, b, B, N", C["grey"]),
    "pent": (520, 160, "Key number K", "S = Pent(B_x)\nK = S^2+S+41", C["lblue"]),
    "chan": (745, 262, "Open channel", "(C1, C2) visible to all", C["lred"]),
    "eve": (520, 262, "Eve (attacker)", "knows B, Pub, C1, C2", C["lorange"]),
    "keygen": (945, 392, "Bob's keys", "d secret, Pub = d*B", C["lorange"]),
    "dec": (745, 392, "PEECC decrypt", "Pm = C2 - d*C1", C["lgreen"]),
    "dko": (520, 392, "Koblitz decode", "point -> bytes", C["lblue"]),
    "out": (295, 392, "Recovered", "message m", C["grey"]),
}
PENT_BODY = {False: "S = Pent(B_x)\nK = S^2+S+41", True: "S = Pent(x), x random\nK = (S^2+S+41) mod N"}
EDGES = [("msg", "kob", "m"), ("kob", "enc", "Pm"), ("params", "pent", "B_x"), ("pent", "enc", "K"),
         ("keygen", "enc", "Pub"), ("enc", "chan", "(C1,C2)"), ("chan", "dec", "(C1,C2)"),
         ("keygen", "dec", "d"), ("dec", "dko", "Pm'"), ("dko", "out", "m"), ("chan", "eve", "copies")]
EDGE_LABEL_AT = {("keygen", "enc"): 0.3}       # label position along the edge (default: middle)
SC = 0.9
NODES = {k: (x * SC, y * SC, a, b, c) for k, (x, y, a, b, c) in NODES.items()}
BW, BH = 178 * SC, 74 * SC


def run_gui():
    import tkinter as tk
    from tkinter import ttk
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    if "--shots" in sys.argv:                      # screenshots are taken in physical pixels
        try:
            import ctypes
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass
    root = tk.Tk()
    root.title("PEECC and the UWC authentication protocol: how it works, and how to improve it")
    root.geometry("%dx%d+10+10" % (min(1440, root.winfo_screenwidth() - 30), min(900, root.winfo_screenheight() - 90)))
    root.configure(bg=C["grey"])
    st = ttk.Style()
    st.theme_use("clam")
    st.configure("TNotebook", background=C["grey"], borderwidth=0)
    st.configure("TNotebook.Tab", padding=(14, 8), font=("Segoe UI", 11, "bold"), background="#D5DBE1")
    st.map("TNotebook.Tab", background=[("selected", C["white"])], foreground=[("selected", C["blue"])])
    st.configure("TFrame", background=C["grey"]); st.configure("TLabel", background=C["grey"], font=("Segoe UI", 10))
    st.configure("TLabelframe", background=C["grey"]); st.configure("TLabelframe.Label", background=C["grey"], font=("Segoe UI", 10, "bold"))
    st.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
    st.configure("Accent.TButton", background=C["blue"], foreground="white")
    st.map("Accent.TButton", background=[("active", "#1F5A99")])
    st.configure("TCheckbutton", background=C["grey"], font=("Segoe UI", 10))
    st.configure("TRadiobutton", background=C["grey"], font=("Segoe UI", 10))
    st.configure("Treeview", font=("Segoe UI", 10), rowheight=26); st.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    hdr = tk.Frame(root, bg=C["navy"]); hdr.pack(fill="x")
    tk.Label(hdr, text="PEECC  -  Pentatope Elliptic Curve Cryptography", bg=C["navy"], fg="white",
             font=("Segoe UI", 18, "bold")).pack(side="left", padx=18, pady=10)
    tk.Label(hdr, text="Base paper [18]  |  secp256r1  |  C: peecc.c / peecc.dll  |  protocol: protocol.py (IoT Sec. IV)", bg=C["navy"], fg="#9FB3C8",
             font=("Segoe UI", 10)).pack(side="left", padx=6)
    badge = tk.Label(hdr, text="", font=("Segoe UI", 11, "bold"), fg="white", padx=14, pady=4)
    badge.pack(side="right", padx=18)

    nb = ttk.Notebook(root); nb.pack(fill="both", expand=True)
    improved_var = tk.BooleanVar(value=False)
    mode_src = {}                                 # tab -> its mode variable (tabs without one follow tab 1)

    def update_badge():
        """The badge shows the mode of the tab that is currently visible."""
        try:
            cur = nb.nametowidget(nb.select())
        except Exception:
            cur = None
        imp = mode_src.get(cur, improved_var).get()
        if imp:
            badge.config(text="IMPROVED  (random pentatope input x)", bg=C["green"])
        else:
            badge.config(text="PAPER-EXACT  (K public)", bg=C["red"])

    # =============================================================== TAB 1
    tab1 = ttk.Frame(nb); nb.add(tab1, text="1  Pipeline (256-bit)")
    S1 = {"steps": [], "i": -1, "auto": None, "anim": None, "token": None, "hist": 0}
    bar = ttk.Frame(tab1); bar.pack(fill="x", padx=10, pady=(8, 2))
    ttk.Label(bar, text="Message (one block, max 29 bytes):").pack(side="left")
    msg_var = tk.StringVar(value="hello world")
    ttk.Entry(bar, textvariable=msg_var, width=26, font=("Segoe UI", 11)).pack(side="left", padx=6)
    ttk.Radiobutton(bar, text="Paper-exact [18]", variable=improved_var, value=False,
                    command=lambda: run()).pack(side="left", padx=(14, 2))
    ttk.Radiobutton(bar, text="Improved (deviation)", variable=improved_var, value=True,
                    command=lambda: run()).pack(side="left", padx=2)
    speed = tk.DoubleVar(value=2.2)
    ttk.Label(bar, text="Delay (s):").pack(side="left", padx=(14, 2))
    ttk.Scale(bar, from_=0.6, to=5.0, variable=speed, length=90).pack(side="left")
    auto_btn = ttk.Button(bar, text="Auto-play", style="Accent.TButton", command=lambda: toggle_auto()); auto_btn.pack(side="right", padx=2)
    ttk.Button(bar, text="Next >", command=lambda: nxt()).pack(side="right", padx=2)
    ttk.Button(bar, text="< Back", command=lambda: prv()).pack(side="right", padx=2)
    ttk.Button(bar, text="Run (new keys)", command=lambda: run()).pack(side="right", padx=(2, 10))

    stepper = tk.Canvas(tab1, height=30, bg=C["grey"], highlightthickness=0); stepper.pack(fill="x", padx=10)
    body = ttk.Frame(tab1); body.pack(fill="both", expand=True, padx=10, pady=4)
    right = tk.Frame(body, bg=C["white"], highlightbackground="#C9D2DA", highlightthickness=1); right.pack(side="right", fill="y", padx=(10, 0))
    left = ttk.Frame(body); left.pack(side="left", fill="both", expand=True)
    cv = tk.Canvas(left, width=int(1100 * SC), height=int(440 * SC), bg=C["white"], highlightthickness=1, highlightbackground="#C9D2DA")
    cv.pack(anchor="w")

    title_lbl = tk.Label(right, text="Press 'Run'", bg=C["white"], fg=C["navy"], font=("Segoe UI", 15, "bold"), wraplength=400, justify="left")
    title_lbl.pack(anchor="w", padx=12, pady=(10, 4))
    plain_lbl = tk.Label(right, text="", bg=C["yellow"], fg="#3A3A3A", font=("Segoe UI", 11), wraplength=396, justify="left", padx=10, pady=8)
    plain_lbl.pack(fill="x", padx=12)
    math_lbl = tk.Label(right, text="", bg=C["white"], fg=C["blue"], font=("Consolas", 10, "bold"), wraplength=400, justify="left")
    math_lbl.pack(anchor="w", padx=12, pady=6)
    vals = tk.Text(right, width=52, height=12, font=("Consolas", 9), wrap="word", bg="#F8FAFB", relief="flat", state="disabled")
    vals.pack(fill="both", expand=True, padx=12, pady=(0, 6))
    vals.tag_configure("k", foreground=C["dgrey"], font=("Segoe UI", 9, "bold"))
    vals.tag_configure("good", foreground=C["green"], font=("Segoe UI", 11, "bold"))
    vals.tag_configure("bad", foreground=C["red"], font=("Segoe UI", 11, "bold"))

    hist_box = ttk.LabelFrame(left, text=" C1 across runs: paper-exact = always identical, improved = always new ")
    hist_box.pack(fill="x", pady=6)
    tree = ttk.Treeview(hist_box, columns=("n", "mode", "c1", "c2", "eve"), show="headings", height=3)
    for c, w, nm in (("n", 34, "#"), ("mode", 100, "mode"), ("c1", 170, "C1.x"), ("c2", 170, "C2.x"), ("eve", 330, "keyless Eve reads the message?")):
        tree.heading(c, text=nm); tree.column(c, width=w, anchor="w")
    tree.tag_configure("bad", foreground=C["red"]); tree.tag_configure("good", foreground=C["green"])
    tree.pack(fill="x", padx=4, pady=4)

    shapes, edge_ids, body_ids, label_ids = {}, {}, {}, {}

    def rrect(x, y, w, h, **kw):
        r = 12
        pts = [x + r, y, x + w - r, y, x + w, y, x + w, y + r, x + w, y + h - r, x + w, y + h, x + w - r, y + h,
               x + r, y + h, x, y + h, x, y + h - r, x, y + r, x, y]
        return cv.create_polygon(pts, smooth=True, **kw)

    def draw_static():
        cv.delete("all")
        W = int(1100 * SC)
        for y0, y1, col, lab in ((8, 215, "#EAF2FB", "ALICE  (sender)"), (225, 318, "#FDECEC", "OPEN CHANNEL  /  ATTACKER"),
                                 (328, 428, "#EAF6EE", "BOB  (receiver, key owner)")):
            cv.create_rectangle(6, y0 * SC, W - 6, y1 * SC, fill=col, outline="")
            cv.create_text(16, (y0 + 12) * SC, text=lab, anchor="w", fill=C["dgrey"], font=("Segoe UI", 9, "bold"))
        for a, b, lab in EDGES:
            ax_, ay = NODES[a][:2]; bx, by = NODES[b][:2]
            dash = (6, 4) if lab in ("d", "copies") else None
            edge_ids[(a, b)] = cv.create_line(ax_, ay, bx, by, arrow="last", width=2, fill="#9AA5B1", dash=dash)
        for k, (x, y, ti, bo, col) in NODES.items():
            shapes[k] = rrect(x - BW / 2, y - BH / 2, BW, BH, fill=col, outline="#7A8794", width=2)
            cv.create_text(x, y - 21 * SC, text=ti, font=("Segoe UI", 10, "bold"), fill=C["navy"], width=BW - 10, justify="center")
            body_ids[k] = cv.create_text(x, y + 11 * SC, text=bo, font=("Segoe UI", 8), fill="#333", justify="center", width=BW - 12)
        for a, b, lab in EDGES:                              # labels on top, in the gaps between the boxes
            ax_, ay = NODES[a][:2]; bx, by = NODES[b][:2]
            f = EDGE_LABEL_AT.get((a, b), 0.5)
            tid = cv.create_text(ax_ + (bx - ax_) * f, ay + (by - ay) * f, text=lab, fill=C["dgrey"], font=("Segoe UI", 8, "italic"))
            bb = cv.bbox(tid)
            rid = cv.create_rectangle(bb[0] - 3, bb[1] - 1, bb[2] + 3, bb[3] + 1, fill="white", outline="")
            cv.tag_lower(rid, tid)
            label_ids[(a, b)] = (tid, rid)
        S1["token"] = None

    draw_static()

    def draw_stepper():
        stepper.delete("all")
        n = len(S1["steps"])
        if not n:
            return
        w = stepper.winfo_width() or 1000
        gap = (w - 40) / max(1, n - 1)
        for i in range(n):
            x = 20 + i * gap
            if i < n - 1:
                stepper.create_line(x, 14, x + gap, 14, fill="#B7C2CC", width=3)
        for i in range(n):
            x = 20 + i * gap
            cur, done = i == S1["i"], i < S1["i"]
            tag = "s%d" % i
            stepper.create_oval(x - 10, 4, x + 10, 24, fill=C["orange"] if cur else (C["blue"] if done else "#D5DBE1"), outline="", tags=tag)
            stepper.create_text(x, 14, text=str(i + 1), fill="white" if (cur or done) else C["dgrey"], font=("Segoe UI", 8, "bold"), tags=tag)
            stepper.tag_bind(tag, "<Button-1>", lambda e, k=i: show_step(k))

    def set_active(active):
        for k in NODES:
            cv.itemconfig(shapes[k], outline="#7A8794", width=2)
        for ln in edge_ids.values():
            cv.itemconfig(ln, fill="#9AA5B1", width=2)
        for k in active:
            cv.itemconfig(shapes[k], outline=C["orange"], width=4)

    def clear_token():
        if S1["token"]:
            for item in S1["token"]:
                cv.delete(item)
        S1["token"] = None
        for ids in label_ids.values():                 # edge labels hidden by an earlier token come back
            for item in ids:
                cv.itemconfig(item, state="normal")

    def border(cx, cy, dx, dy):
        """Point where a line from the box centre (cx, cy) in direction (dx, dy) leaves the box."""
        t = min((BW / 2) / abs(dx) if dx else 1e9, (BH / 2) / abs(dy) if dy else 1e9)
        return cx + dx * t, cy + dy * t

    def animate(src, dst, label):
        """Token travels from the source box border to the destination box border; its label stays outside the boxes."""
        clear_token()
        (cx0, cy0), (cx1, cy1) = NODES[src][:2], NODES[dst][:2]
        dx, dy = cx1 - cx0, cy1 - cy0
        x0, y0 = border(cx0, cy0, dx, dy)
        x1, y1 = border(cx1, cy1, -dx, -dy)
        horizontal = abs(dx) >= abs(dy)              # horizontal: label pinned in the gap between the boxes
        gap = ((x0 + x1) / 2, (y0 + y1) / 2 - 14)
        off = (12, -12 if dy > 0 else 12)            # vertical: label beside the moving token
        o = cv.create_oval(x0 - 8, y0 - 8, x0 + 8, y0 + 8, fill=C["orange"], outline="white", width=2)
        tb = cv.create_rectangle(0, 0, 1, 1, fill="white", outline=C["orange"])
        tx = cv.create_text(*(gap if horizontal else (x0 + off[0], y0 + off[1])), text=label, anchor="center" if horizontal else "w",
                            fill=C["orange"], font=("Segoe UI", 10, "bold"))
        S1["token"] = (o, tb, tx)
        if (src, dst) in edge_ids:
            cv.itemconfig(edge_ids[(src, dst)], fill=C["orange"], width=4)
            for item in label_ids[(src, dst)]:          # the token's own label replaces the static one
                cv.itemconfig(item, state="hidden")
        frames = 30

        def tick(n=0):
            f = n / frames
            f = f * f * (3 - 2 * f)
            x, y = x0 + (x1 - x0) * f, y0 + (y1 - y0) * f
            cv.coords(o, x - 8, y - 8, x + 8, y + 8)
            if not horizontal:
                cv.coords(tx, x + off[0], y + off[1])
            bb = cv.bbox(tx); cv.coords(tb, bb[0] - 4, bb[1] - 2, bb[2] + 4, bb[3] + 2)
            if n < frames:
                S1["anim"] = root.after(16, tick, n + 1)
        tick()

    def show_step(i):
        steps = S1["steps"]
        if not steps or not (0 <= i < len(steps)):
            return
        S1["i"] = i
        s = steps[i]
        title_lbl.config(text="Step %d/%d:  %s" % (i + 1, len(steps), s["title"]))
        plain_lbl.config(text=s["plain"])
        math_lbl.config(text="\n".join(p.strip() for p in s["math"].replace(";", "   ").split("   ") if p.strip()))
        set_active(s["active"])
        if S1["anim"]:
            root.after_cancel(S1["anim"])
        if s["token"]:
            animate(*s["token"])
        else:
            clear_token()
        vals.configure(state="normal"); vals.delete("1.0", "end")
        for k, v in s["values"]:
            vals.insert("end", k + "\n", "k"); vals.insert("end", "   " + str(v).replace("\n", "\n   ") + "\n")
        if s["verdict"]:
            vals.insert("end", "\n" + s["verdict"][1] + "\n", s["verdict"][0])
        vals.configure(state="disabled")
        draw_stepper()

    def run():
        stop_auto()
        update_badge()
        data = msg_var.get().encode("utf-8")
        if len(data) > 29:
            title_lbl.config(text="Message too long: this tab shows one block (max 29 bytes); peecc.c splits longer messages"); return
        t = build_real_trace(data, improved_var.get())
        cv.itemconfig(body_ids["pent"], text=PENT_BODY[improved_var.get()])
        S1["steps"] = real_steps(t)
        S1["hist"] += 1
        broke = t["eve"] == data
        tree.insert("", 0, values=(S1["hist"], "improved" if t["improved"] else "paper-exact", short(t["C1"][0], 8), short(t["C2"][0], 8),
                                   ("YES - read \"%s\"" % t["eve"].decode("utf-8", "replace")) if broke else "no - attack fails"),
                    tags=("bad" if broke else "good",))
        show_step(0)

    def nxt():
        if S1["steps"] and S1["i"] < len(S1["steps"]) - 1:
            show_step(S1["i"] + 1)
        else:
            stop_auto()

    def prv():
        if S1["i"] > 0:
            show_step(S1["i"] - 1)

    def stop_auto():
        if S1["auto"]:
            root.after_cancel(S1["auto"])
        S1["auto"] = None
        auto_btn.config(text="Auto-play")

    def auto_tick():
        if S1["auto"] is None:
            return
        if S1["i"] >= len(S1["steps"]) - 1:
            stop_auto(); return
        nxt()
        S1["auto"] = root.after(int(speed.get() * 1000), auto_tick)

    def toggle_auto():
        if S1["auto"] is not None:
            stop_auto(); return
        if not S1["steps"]:
            run()
        elif S1["i"] >= len(S1["steps"]) - 1:
            show_step(0)
        auto_btn.config(text="Pause")
        S1["auto"] = root.after(int(speed.get() * 1000), auto_tick)

    stepper.bind("<Configure>", lambda e: draw_stepper())

    # =============================================================== TAB 2 (toy curve explorer)
    tab2 = ttk.Frame(nb); nb.add(tab2, text="2  Toy curve")
    E2, pts2 = make_toy()
    msgs2 = toy_valid_messages(E2)
    mult2 = toy_multiples(E2)
    T2 = {"frames": [], "i": 0, "auto": None}
    ctrl = ttk.LabelFrame(tab2, text=" Choose the secrets ")
    ctrl.pack(side="right", fill="y", padx=(0, 10), pady=8)
    left2 = ttk.Frame(tab2); left2.pack(side="left", fill="both", expand=True, padx=(10, 6), pady=8)
    d_var = tk.IntVar(value=min(7, E2.N - 1)); m_var = tk.IntVar(value=msgs2[0]); r_var = tk.IntVar(value=5)
    mode2 = tk.BooleanVar(value=False); lab_var = tk.BooleanVar(value=True)
    row = ttk.Frame(ctrl); row.pack(fill="x", padx=8, pady=(8, 2))
    ttk.Label(row, text="Bob's private key d:").pack(side="left")
    ttk.Spinbox(row, from_=1, to=E2.N - 1, textvariable=d_var, width=4, command=lambda: rebuild2()).pack(side="left", padx=4)
    row = ttk.Frame(ctrl); row.pack(fill="x", padx=8, pady=2)
    ttk.Label(row, text="Alice's message number m:").pack(side="left")
    cb = ttk.Combobox(row, values=msgs2, textvariable=m_var, width=4, state="readonly"); cb.pack(side="left", padx=4)
    cb.bind("<<ComboboxSelected>>", lambda e: rebuild2())
    ttk.Radiobutton(ctrl, text="Paper-exact (public K)", variable=mode2, value=False, command=lambda: rebuild2()).pack(anchor="w", padx=8, pady=(8, 0))
    ttk.Radiobutton(ctrl, text="Improved (one-time random pentatope input x)", variable=mode2, value=True, command=lambda: rebuild2()).pack(anchor="w", padx=8)
    row = ttk.Frame(ctrl); row.pack(fill="x", padx=8, pady=2)
    ttk.Label(row, text="   x =").pack(side="left")
    ttk.Spinbox(row, from_=1, to=E2.N - 1, textvariable=r_var, width=4, command=lambda: rebuild2()).pack(side="left")
    ttk.Checkbutton(ctrl, text="label every dot with its k  (dot = k*B)", variable=lab_var, command=lambda: draw2()).pack(anchor="w", padx=8, pady=6)
    lst = tk.Listbox(ctrl, height=8, font=("Segoe UI", 10), activestyle="none", exportselection=False, bg="white")
    lst.pack(fill="x", padx=8, pady=4)
    lst.bind("<<ListboxSelect>>", lambda e: set_i2(lst.curselection()[0]) if lst.curselection() else None)
    nav = ttk.Frame(ctrl); nav.pack(fill="x", padx=8, pady=4)
    ttk.Button(nav, text="< Back", command=lambda: step2(-1)).pack(side="left", padx=2)
    ttk.Button(nav, text="Next >", command=lambda: step2(1)).pack(side="left", padx=2)
    play2 = ttk.Button(nav, text="Play", style="Accent.TButton", command=lambda: toggle2()); play2.pack(side="left", padx=2)
    plain2 = tk.Label(ctrl, text="", bg=C["yellow"], font=("Segoe UI", 11), wraplength=330, justify="left", padx=10, pady=8)
    plain2.pack(fill="x", padx=8, pady=4)
    math2 = tk.Label(ctrl, text="", bg=C["grey"], fg=C["blue"], font=("Consolas", 9, "bold"), wraplength=330, justify="left")
    math2.pack(anchor="w", padx=8, pady=2)
    verdict2 = tk.Label(ctrl, text="", bg=C["grey"], font=("Segoe UI", 11, "bold"), wraplength=330, justify="left")
    verdict2.pack(anchor="w", padx=8, pady=4)
    fig = Figure(figsize=(6.0, 4.7), dpi=100, facecolor="white")
    ax = fig.add_subplot(111)
    canvas2 = FigureCanvasTkAgg(fig, master=left2)
    canvas2.get_tk_widget().config(width=600, height=470)
    canvas2.get_tk_widget().pack(fill="both", expand=True)

    def set_i2(i):
        T2["i"] = i; draw2()

    def draw2():
        if not T2["frames"]:
            return
        fr = T2["frames"][T2["i"]]
        ax.clear()
        ax.set_xlim(-1.5, E2.p + 0.5); ax.set_ylim(-1.5, E2.p + 0.5); ax.set_aspect("equal")
        ax.set_xticks(range(0, E2.p, 2)); ax.set_yticks(range(0, E2.p, 2)); ax.grid(alpha=0.18)
        ax.set_facecolor("#FAFBFC")
        for sp in ax.spines.values():
            sp.set_color("#C9D2DA")
        ax.set_title("y\u00b2 = x\u00b3 + x + 1 (mod 23)    -    %s" % fr["title"], fontsize=12, fontweight="bold", color=C["navy"])
        ch = fr["chain"]
        chain_set = set(ch)
        rest = [p for p in pts2 if p not in chain_set]
        ax.scatter([p[0] for p in rest], [p[1] for p in rest], s=150, c="#D5DDE5", zorder=2, edgecolors="white")
        if len(ch) > 1:
            ax.plot([c[0] for c in ch], [c[1] for c in ch], "-", c=C["orange"], lw=1.2, alpha=0.7, zorder=3)
        if ch:
            ax.scatter([c[0] for c in ch], [c[1] for c in ch], s=150, c=C["lorange"], edgecolors=C["orange"], linewidths=1.6, zorder=4)
        if lab_var.get():                                   # the number inside each dot is its k  (dot = k*B)
            for P, k in mult2.items():
                ax.text(P[0], P[1], str(k), ha="center", va="center", fontsize=7, color="#2C3640", fontweight="bold", zorder=5)
        for a_, b_ in fr["arrows"]:
            if a_ and b_ and a_ != b_:
                ax.annotate("", xy=b_, xytext=a_, arrowprops=dict(arrowstyle="-|>", color=C["blue"], lw=2.0, shrinkA=9, shrinkB=9), zorder=5)
        groups = {}
        for lab, P in fr["marks"].items():                 # one ring + one callout per distinct point
            if P is not None:
                groups.setdefault(P, []).append(lab)
        cols = [C["blue"], C["orange"], C["green"], C["red"], "#8E44AD", "#16A085", "#7F8C8D"]
        offs = [(26, 24), (-26, 24), (26, -24), (-26, -24), (0, 34), (0, -34)]
        for n, (P, labs) in enumerate(groups.items()):
            col = cols[n % len(cols)]
            ax.scatter([P[0]], [P[1]], s=430, facecolors="none", edgecolors=col, linewidths=2.6, zorder=6)
            ax.annotate(" = ".join(labs), P, xytext=offs[n % len(offs)], textcoords="offset points", fontsize=9, color=col,
                        fontweight="bold", zorder=8, ha="center", va="center",
                        bbox=dict(boxstyle="round,pad=0.25", fc="white", ec=col, lw=1.2),
                        arrowprops=dict(arrowstyle="-", color=col, lw=1.2, shrinkA=0, shrinkB=11))
        fig.tight_layout()
        canvas2.draw_idle()
        plain2.config(text=fr["plain"]); math2.config(text=fr["math"])
        if "good" in fr:
            verdict2.config(text=("Eve FAILS - message safe" if fr["good"] else "Eve SUCCEEDS - message exposed"),
                            fg=C["green"] if fr["good"] else C["red"])
        else:
            verdict2.config(text="")
        lst.selection_clear(0, "end"); lst.selection_set(T2["i"]); lst.see(T2["i"])

    def rebuild2():
        update_badge()
        T2["frames"] = build_toy_frames(E2, pts2, max(1, min(E2.N - 1, int(d_var.get()))), int(m_var.get()), mode2.get(), int(r_var.get()))
        lst.delete(0, "end")
        for n, f in enumerate(T2["frames"], 1):
            lst.insert("end", "%d. %s" % (n, f["title"]))
        T2["i"] = min(T2["i"], len(T2["frames"]) - 1)
        draw2()

    def step2(dl):
        T2["i"] = max(0, min(len(T2["frames"]) - 1, T2["i"] + dl)); draw2()

    def play_tick():
        if T2["auto"] is None:
            return
        if T2["i"] >= len(T2["frames"]) - 1:
            toggle2(); return
        step2(1); T2["auto"] = root.after(1800, play_tick)

    def toggle2():
        if T2["auto"] is not None:
            root.after_cancel(T2["auto"]); T2["auto"] = None; play2.config(text="Play"); return
        if T2["i"] >= len(T2["frames"]) - 1:
            T2["i"] = 0; draw2()
        play2.config(text="Pause"); T2["auto"] = root.after(1800, play_tick)

    rebuild2()

    # =============================================================== TAB 3 (improvements)
    tab3 = ttk.Frame(nb); nb.add(tab3, text="4  Improvements")
    top3 = tk.Frame(tab3, bg=C["white"], highlightbackground="#C9D2DA", highlightthickness=1)
    top3.pack(fill="x", padx=10, pady=(8, 4))
    tk.Label(top3, text="What we change relative to the base paper [18]   (deviations: the paper's own scheme is the left column)",
             bg=C["white"], fg=C["navy"], font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(8, 2))
    for txt_ in ("1.  Pentatope input x is a fresh secret random number instead of B_x   ->  the paper's K is computable by anybody, the new K is not.",
                 "2.  Validate C1 and C2 (on curve, in range) before using them   ->  the paper-exact mode never checks (finding F4).",
                 "3.  K is reduced mod N (256 bit instead of 2029 bit)   ->  same points, about 8x fewer point operations per encryption.",
                 "4.  Points are sent compressed (02/03 || x, 33 instead of 64 bytes)   ->  528 instead of 1024 bit per ciphertext block.",
                 "Not fixed by either scheme: no authentication / integrity tag, not constant-time, blocks of a long message are independent."):
        tk.Label(top3, text=txt_, bg=C["white"], fg="#333" if not txt_.startswith("Not") else C["red"], font=("Segoe UI", 10),
                 anchor="w", justify="left").pack(anchor="w", padx=18)
    tk.Label(top3, text="", bg=C["white"]).pack()

    ctl3 = ttk.Frame(tab3); ctl3.pack(fill="x", padx=10, pady=4)
    n_var = tk.IntVar(value=12)
    ttk.Label(ctl3, text="Trials (random messages, random keys):").pack(side="left")
    ttk.Spinbox(ctl3, from_=4, to=60, textvariable=n_var, width=5).pack(side="left", padx=6)
    go3 = ttk.Button(ctl3, text="Run live benchmark", style="Accent.TButton", command=lambda: start_bench()); go3.pack(side="left", padx=8)
    prog = ttk.Progressbar(ctl3, length=240, mode="determinate"); prog.pack(side="left", padx=6)
    status3 = ttk.Label(ctl3, text="Press the button: both schemes are run live in this program (pure-Python implementation).")
    status3.pack(side="left", padx=8)

    mid3 = ttk.Frame(tab3); mid3.pack(fill="both", expand=True, padx=10, pady=4)
    leftm = ttk.Frame(mid3); leftm.pack(side="left", fill="both", expand=True)
    st.configure("Tab4.Treeview", font=("Segoe UI", 10), rowheight=22)
    tq = ttk.Treeview(leftm, columns=("m", "a", "b", "c"), show="headings", height=8, style="Tab4.Treeview")
    for c, w, nm in (("m", 270, "Quantitative metric (measured live)"), ("a", 150, "Base paper [18]"), ("b", 150, "Improved"), ("c", 150, "Change")):
        tq.heading(c, text=nm); tq.column(c, width=w, anchor="w")
    tq.tag_configure("good", foreground=C["green"]); tq.pack(fill="x")
    tql = ttk.Treeview(leftm, columns=("p", "a", "b", "e"), show="headings", height=10, style="Tab4.Treeview")
    for c, w, nm in (("p", 250, "Qualitative property"), ("a", 110, "Base paper [18]"), ("b", 110, "Improved"), ("e", 270, "Evidence")):
        tql.heading(c, text=nm); tql.column(c, width=w, anchor="w")
    tql.tag_configure("yes", foreground=C["green"]); tql.tag_configure("no", foreground=C["red"]); tql.tag_configure("same", foreground=C["dgrey"])
    for p_, a_, b_, e_, tg in (
            ("Confidential against a passive eavesdropper", "NO", "YES", "live: keyless Eve success rate", "yes"),
            ("Same message twice -> different ciphertext", "NO", "YES", "live metric above", "yes"),
            ("Ciphertexts unlinkable (C1 differs)", "NO", "YES", "live: distinct C1 count", "yes"),
            ("Rejects off-curve / forged points", "NO", "YES", "peecc.c --hardened / pt_valid; selftest", "yes"),
            ("Compact ciphertext (528 bit/block)", "NO", "YES", "compressed points 02/03 || x", "yes"),
            ("Keeps the pentatope + Euler key derivation", "YES", "YES", "only the input x changes (B_x -> random)", "same"),
            ("Follows the paper's key derivation exactly", "YES", "NO", "x = B_x replaced by a random x on purpose", "no"),
            ("Message authentication / integrity", "NO", "NO", "neither scheme has a tag - future work", "same"),
            ("Constant-time / side-channel safe", "NO", "NO", "neither (educational code)", "same"),
            ("Message size per block (longer messages: several blocks)", "29 B", "29 B", "unchanged", "same")):
        tql.insert("", "end", values=(p_, a_, b_, e_), tags=(tg,))
    tql.pack(fill="x", pady=(8, 0))
    fig3 = Figure(figsize=(4.4, 5.6), dpi=100, facecolor="white")
    canvas3 = FigureCanvasTkAgg(fig3, master=mid3)
    canvas3.get_tk_widget().config(width=400, height=520)
    canvas3.get_tk_widget().pack(side="right", fill="both", padx=(10, 0))

    B3 = {"i": 0, "res": {False: [], True: []}, "n": 0}

    def draw3():
        fig3.clear()
        res = B3["res"]
        if not res[False]:
            canvas3.draw_idle(); return
        names, cols = ["Base paper\n[18]", "Improved"], [C["red"], C["green"]]
        eve = [100.0 * sum(r["eve"] for r in res[m]) / len(res[m]) for m in (False, True)]
        ms = [sum(r["ms"] for r in res[m]) / len(res[m]) for m in (False, True)]
        dist = [len({r["c1"] for r in res[m]}) for m in (False, True)]
        for k, (vals_, ttl, yl) in enumerate(((eve, "Eve decrypts WITHOUT the key (%)", "%"),
                                              (ms, "Encryption time (ms, Python)", "ms"),
                                              (dist, "Distinct C1 values in %d messages" % len(res[False]), "count"))):
            a = fig3.add_subplot(3, 1, k + 1)
            bars = a.bar(names, vals_, color=cols, width=0.55)
            a.set_title(ttl, fontsize=10, fontweight="bold", color=C["navy"]); a.set_ylabel(yl, fontsize=8)
            for sp in ("top", "right"):
                a.spines[sp].set_visible(False)
            for b, v in zip(bars, vals_):
                a.text(b.get_x() + b.get_width() / 2, v, ("%.0f" % v) if k != 1 else ("%.1f" % v), ha="center", va="bottom", fontsize=9, fontweight="bold")
            a.set_ylim(0, (max(vals_) * 1.3) or 1)
        fig3.tight_layout()
        canvas3.draw_idle()

    def finish_bench():
        res = B3["res"]
        n = len(res[False])
        eve = [100.0 * sum(r["eve"] for r in res[m]) / n for m in (False, True)]
        ms = [sum(r["ms"] for r in res[m]) / n for m in (False, True)]
        dist = [len({r["c1"] for r in res[m]}) for m in (False, True)]
        same = [sum(r["same"] for r in res[m]) for m in (False, True)]
        bits = [max(r["scalar_bits"] for r in res[m]) for m in (False, True)]
        ops0, ops1 = bits[0] + 1038, bits[1] + bits[1] // 2
        for iid in tq.get_children():
            tq.delete(iid)
        rows = [("Keyless Eve recovers the message", "%.0f %%  (%d/%d)" % (eve[0], round(eve[0] * n / 100), n),
                 "%.0f %%  (%d/%d)" % (eve[1], round(eve[1] * n / 100), n), "-%.0f points" % (eve[0] - eve[1])),
                ("Distinct C1 over %d messages" % n, "%d of %d" % (dist[0], n), "%d of %d" % (dist[1], n), "unlinkable"),
                ("Same msg + key twice: identical ciphertext", "%d of %d" % (same[0], n), "%d of %d" % (same[1], n), "randomised"),
                ("Multiplier size (bits)", "%d" % bits[0], "%d (max)" % bits[1], "%.1fx smaller" % (bits[0] / bits[1])),
                ("Point operations per scalar mult. (derived)", "~%d" % ops0, "~%d" % ops1, "~%.1fx fewer" % (ops0 / ops1)),
                ("Encrypt time, this Python program", "%.1f ms" % ms[0], "%.1f ms" % ms[1], "%.1fx faster" % (ms[0] / ms[1])),
                ("Decryption still correct", "%d of %d" % (sum(r["ok"] for r in res[False]), n), "%d of %d" % (sum(r["ok"] for r in res[True]), n), "no loss")]
        cb = c_bench()
        if cb:
            rows.insert(6, ("Encrypt time, peecc.c (measured now)", "%.2f ms" % cb[False][1], "%.2f ms" % cb[True][1],
                            "%.1fx faster" % (cb[False][1] / cb[True][1])))
        else:
            rows.insert(6, ("Encrypt time, peecc.c (earlier, est.)", "%.1f ms" % C_REF["encrypt_ms"], "~%.1f ms (est.)" % (2 * C_REF["mul_256_ms"]),
                            "~%.0fx faster (est.)" % (C_REF["encrypt_ms"] / (2 * C_REF["mul_256_ms"]))))
        for r_ in rows:
            tq.insert("", "end", values=r_, tags=("good",))
        status3.config(text="Done: %d trials per scheme. %s" % (n, "peecc.c row: measured now (peecc.dll)."
                       if cb else "peecc.dll not built (make lib): peecc.c row = earlier measurement; 'est.' = 2 x 256-bit multiplication."))
        go3.config(state="normal")
        draw3()

    def bench_tick():
        i, n = B3["i"], B3["n"]
        if i >= n:
            finish_bench(); return
        msg_ = secrets.token_bytes(6).hex().encode()
        B3["res"][False].append(bench_trial(REAL, False, msg_))
        B3["res"][True].append(bench_trial(REAL, True, msg_))
        B3["i"] += 1; prog["value"] = 100.0 * B3["i"] / n
        status3.config(text="running trial %d / %d ..." % (B3["i"], n))
        root.after(10, bench_tick)

    def start_bench():
        B3.update(i=0, n=max(4, min(60, int(n_var.get()))), res={False: [], True: []})
        go3.config(state="disabled"); prog["value"] = 0
        root.after(30, bench_tick)

    # =============================================================== TAB 4 (performance metrics)
    tab4 = ttk.Frame(nb); nb.add(tab4, text="5  Metrics")
    top4 = tk.Frame(tab4, bg=C["white"], highlightbackground="#C9D2DA", highlightthickness=1)
    top4.pack(fill="x", padx=10, pady=(8, 4))
    tk.Label(top4, text="Metrics used to evaluate an ECC / PEECC scheme", bg=C["white"], fg=C["navy"],
             font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(8, 2))
    for t_ in ("Computation cost: time per operation (ms) and number of scalar multiplications / point operations - as in the cost tables of the UWC-N paper (Table V uses T_ecm).",
               "Communication and storage cost: key and ciphertext size in bits, ciphertext expansion - as in the UWC-N paper (Table IV, sizes in bits).",
               "Security: ECDLP security level of the curve, plus measured resistance to a passive (keyless) eavesdropper and ciphertext uniqueness.",
               "Times: pure-Python version of the same formulas, plus rows measured in C through peecc.dll (counts and ratios are comparable)."):
        tk.Label(top4, text=t_, bg=C["white"], fg="#333", font=("Segoe UI", 9), anchor="w", justify="left").pack(anchor="w", padx=18)
    ctl4 = ttk.Frame(tab4); ctl4.pack(fill="x", padx=10, pady=4)
    n4 = tk.IntVar(value=12)
    ttk.Label(ctl4, text="Trials:").pack(side="left")
    ttk.Spinbox(ctl4, from_=4, to=60, textvariable=n4, width=5).pack(side="left", padx=6)
    go4 = ttk.Button(ctl4, text="Measure metrics", style="Accent.TButton", command=lambda: start_met()); go4.pack(side="left", padx=8)
    prog4 = ttk.Progressbar(ctl4, length=240, mode="determinate"); prog4.pack(side="left", padx=6)
    status4 = ttk.Label(ctl4, text="Press the button (random keys, message 'hello world')."); status4.pack(side="left", padx=8)
    cols4 = ("m", "u", "a", "b", "s")
    st.configure("Compact.Treeview", font=("Segoe UI", 9), rowheight=21)
    tm = ttk.Treeview(tab4, columns=cols4, show="headings", height=20, style="Compact.Treeview")
    for c, w, nm in (("m", 420, "Metric"), ("u", 70, "Unit"), ("a", 170, "Base paper [18]"), ("b", 170, "Improved"), ("s", 190, "How obtained")):
        tm.heading(c, text=nm); tm.column(c, width=w, anchor="w" if c in ("m", "s") else "center")
    tm.tag_configure("diff", foreground=C["green"])
    tm.pack(fill="x", padx=10, pady=4)
    note4 = tk.Label(tab4, text="", bg=C["grey"], fg="#222", font=("Segoe UI", 10), justify="left", anchor="w", wraplength=1200)
    note4.pack(fill="x", padx=12, pady=6)
    M4 = {"i": 0, "n": 0, "res": {False: [], True: []}}

    def finish_met():
        for iid in tm.get_children():
            tm.delete(iid)
        rows4 = metrics_table(REAL, M4["res"])
        cb = c_bench()
        if cb:
            for j, name in enumerate(("Key generation", "Encryption (one block)", "Decryption (one block)")):
                rows4.insert(3 + j, ("%s time, peecc.c" % name, "ms", "%.3f" % cb[False][j], "%.3f" % cb[True][j], "measured (C, peecc_bench)"))
        for row in rows4:
            tm.insert("", "end", values=row, tags=("diff",) if row[2] != row[3] else ())
        note4.config(text="Green rows differ between the schemes. " + (
            "The peecc.c rows are measured now through peecc.dll (peecc_bench). " if cb else
            "peecc.dll not built (make lib); earlier C measurement: encrypt %.1f ms, pt_mul 2029-bit K %.2f ms vs %.2f ms "
            "with a 256-bit scalar. " % (C_REF["encrypt_ms"], C_REF["mul_2029_ms"], C_REF["mul_256_ms"])) +
            "Sizes, decryption cost and the curve's ECDLP level are identical in both schemes; neither scheme has an "
            "integrity tag. Messages longer than 29 bytes take one block per started 29 bytes (peecc.c): 1024 bit with the "
            "paper's 512-bit points, 528 bit with compressed points (improved). "
            "Protocol-level metrics (M1-M12: 16 384 bit on the wire paper-exact, 8 448 bit improved) are in tab 6 and tab 7.")
        status4.config(text="Done: %d trials per scheme." % M4["n"]); go4.config(state="normal")

    def met_tick():
        if M4["i"] >= M4["n"]:
            finish_met(); return
        for m in (False, True):
            M4["res"][m].append(metrics_trial(REAL, m, b"hello world"))
        M4["i"] += 1; prog4["value"] = 100.0 * M4["i"] / M4["n"]
        status4.config(text="trial %d / %d ..." % (M4["i"], M4["n"]))
        root.after(5, met_tick)

    def start_met():
        M4.update(i=0, n=int(n4.get()), res={False: [], True: []})
        go4.config(state="disabled"); prog4["value"] = 0
        root.after(20, met_tick)

    # =============================================================== TAB 5 (math walkthrough, node by node)
    tab5 = ttk.Frame(nb); nb.insert(2, tab5, text="3  Math walkthrough")
    EM = make_math_curve()
    ptsM = [(xx, yy) for xx in range(EM.p) for yy in range(EM.p) if (yy * yy - (xx ** 3 + xx + 1)) % EM.p == 0]
    multM = toy_multiples(EM)
    validM = toy_valid_messages(EM)
    W5 = {"steps": [], "i": 0, "auto": None}
    bar5 = ttk.Frame(tab5); bar5.pack(fill="x", padx=10, pady=(8, 2))
    d5 = tk.IntVar(value=3); m5 = tk.IntVar(value=3 if 3 in validM else validM[0]); r5 = tk.IntVar(value=10); mode5 = tk.BooleanVar(value=True)
    ttk.Label(bar5, text="Bob's secret d:").pack(side="left")
    ttk.Spinbox(bar5, from_=1, to=EM.N - 1, textvariable=d5, width=4, command=lambda: rebuild5()).pack(side="left", padx=(4, 12))
    ttk.Label(bar5, text="Message number m:").pack(side="left")
    cb5 = ttk.Combobox(bar5, values=validM, textvariable=m5, width=4, state="readonly"); cb5.pack(side="left", padx=(4, 12))
    cb5.bind("<<ComboboxSelected>>", lambda e: rebuild5())
    ttk.Radiobutton(bar5, text="Paper-exact [18]", variable=mode5, value=False, command=lambda: rebuild5()).pack(side="left")
    ttk.Radiobutton(bar5, text="Improved:  x =", variable=mode5, value=True, command=lambda: rebuild5()).pack(side="left", padx=(8, 0))
    ttk.Spinbox(bar5, from_=1, to=EM.N - 1, textvariable=r5, width=4, command=lambda: rebuild5()).pack(side="left", padx=4)
    play5 = ttk.Button(bar5, text="Play", style="Accent.TButton", command=lambda: toggle5()); play5.pack(side="right", padx=2)
    ttk.Button(bar5, text="Next >", command=lambda: step5(1)).pack(side="right", padx=2)
    ttk.Button(bar5, text="< Back", command=lambda: step5(-1)).pack(side="right", padx=2)
    body5 = ttk.Frame(tab5); body5.pack(fill="both", expand=True, padx=10, pady=4)
    lst5 = tk.Listbox(body5, width=34, font=("Segoe UI", 10), activestyle="none", exportselection=False, bg="white")
    lst5.pack(side="left", fill="y")
    lst5.bind("<<ListboxSelect>>", lambda e: (W5.__setitem__("i", lst5.curselection()[0]), draw5()) if lst5.curselection() else None)
    right5 = tk.Frame(body5, bg=C["white"], highlightbackground="#C9D2DA", highlightthickness=1)
    right5.pack(side="right", fill="both", padx=(8, 0))
    mid5 = ttk.Frame(body5); mid5.pack(side="left", fill="both", expand=True, padx=8)
    flow = tk.Canvas(mid5, width=560, height=235, bg=C["white"], highlightthickness=1, highlightbackground="#C9D2DA")
    flow.pack(fill="x")
    fig5 = Figure(figsize=(4.6, 3.5), dpi=100, facecolor="white")
    ax5 = fig5.add_subplot(111)
    canvas5 = FigureCanvasTkAgg(fig5, master=mid5)
    canvas5.get_tk_widget().config(width=480, height=320)
    canvas5.get_tk_widget().pack(fill="both", expand=True, pady=(6, 0))
    title5 = tk.Label(right5, text="", bg=C["white"], fg=C["navy"], font=("Segoe UI", 14, "bold"), wraplength=470, justify="left")
    title5.pack(anchor="w", padx=10, pady=(8, 2))
    words5 = tk.Label(right5, text="", bg=C["yellow"], fg="#333", font=("Segoe UI", 10), wraplength=460, justify="left", padx=8, pady=6)
    words5.pack(fill="x", padx=10)
    tk.Label(right5, text="Core maths", bg=C["white"], fg=C["dgrey"], font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(6, 0))
    maths5 = tk.Label(right5, text="", bg=C["white"], fg=C["blue"], font=("Consolas", 10, "bold"), wraplength=470, justify="left")
    maths5.pack(anchor="w", padx=10)
    tk.Label(right5, text="The computation, number by number", bg=C["white"], fg=C["dgrey"], font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(6, 0))
    comp5 = tk.Text(right5, width=62, height=16, font=("Consolas", 9), wrap="word", bg="#F8FAFB", relief="flat", state="disabled")
    comp5.pack(fill="both", expand=True, padx=10, pady=(0, 8))
    comp5.tag_configure("good", foreground=C["green"], font=("Consolas", 10, "bold"))
    comp5.tag_configure("bad", foreground=C["red"], font=("Consolas", 10, "bold"))
    NODE5 = {"Everyone": 0, "Alice": 0, "Channel": 1, "Bob": 2, "Eve": 3}
    NODE_COL = {"Alice": C["lblue"], "Channel": C["lred"], "Bob": C["lorange"], "Eve": "#EBDDF3"}

    def box(cv_, x, y, w, h, text, fill, outline, bold=False, size=9):
        r_ = 10
        pts_ = [x + r_, y, x + w - r_, y, x + w, y, x + w, y + r_, x + w, y + h - r_, x + w, y + h, x + w - r_, y + h,
                x + r_, y + h, x, y + h, x, y + h - r_, x, y + r_, x, y]
        cv_.create_polygon(pts_, smooth=True, fill=fill, outline=outline, width=3 if bold else 1)
        cv_.create_text(x + w / 2, y + h / 2, text=text, font=("Segoe UI", size, "bold" if bold else "normal"), width=w - 10, justify="center")

    def draw5():
        if not W5["steps"]:
            return
        st_ = W5["steps"][W5["i"]]
        flow.delete("all")
        flow.create_text(8, 10, anchor="w", text="Who computes this step?", fill=C["dgrey"], font=("Segoe UI", 9, "bold"))
        names = ["Alice", "Open channel", "Bob", "Eve"]
        for n, nm in enumerate(names):
            cur = (nm.startswith(st_["node"]) or (st_["node"] == "Everyone"))
            col = ["Alice", "Channel", "Bob", "Eve"][n]
            box(flow, 10 + n * 137, 24, 125, 40, nm + ("\n(secret d)" if nm == "Bob" else "\n(sender)" if nm == "Alice" else "\n(public)" if nm == "Open channel" else "\n(attacker)"),
                NODE_COL[col] if cur else "#F3F5F7", C["orange"] if cur else "#C9D2DA", bold=cur, size=9)
        flow.create_text(8, 84, anchor="w", text="What happens inside:", fill=C["dgrey"], font=("Segoe UI", 9, "bold"))
        box(flow, 10, 100, 160, 100, "INPUT\n" + "\n".join(st_["inputs"]), "#F3F5F7", "#9AA5B1")
        box(flow, 205, 100, 160, 100, "OPERATION\n" + st_["op"], C["lgreen"], C["green"], bold=True)
        box(flow, 400, 100, 150, 100, "OUTPUT\n" + "\n".join(st_["outputs"]), C["lorange"], C["orange"])
        flow.create_line(170, 150, 205, 150, arrow="last", width=3, fill=C["dgrey"])
        flow.create_line(365, 150, 400, 150, arrow="last", width=3, fill=C["dgrey"])
        flow.create_text(280, 218, text="Step %d of %d   -   node: %s" % (W5["i"] + 1, len(W5["steps"]), st_["node"]), fill=C["navy"],
                         font=("Segoe UI", 10, "bold"))
        title5.config(text=st_["title"]); words5.config(text=st_["words"]); maths5.config(text="\n".join(st_["maths"]))
        comp5.configure(state="normal"); comp5.delete("1.0", "end")
        for ln in st_["trace"]:
            tag = ("good",) if ("MATCH" in ln and "MISMATCH" not in ln) or "FAILS (message safe)" in ln else ("bad",) if "SUCCEEDS" in ln or "MISMATCH" in ln else ()
            comp5.insert("end", ln + "\n", tag)
        comp5.configure(state="disabled")
        ax5.clear()
        draw_toy(ax5, EM, ptsM, multM, st_, True, dot=78, font=6, ring=250)
        ax5.set_title("y\u00b2 = x\u00b3 + x + 1 (mod 23),  B = (18, 3):  dot label = k  (dot = k*B)", fontsize=9, color=C["navy"])
        fig5.tight_layout(); canvas5.draw_idle()
        lst5.selection_clear(0, "end"); lst5.selection_set(W5["i"]); lst5.see(W5["i"])

    def rebuild5():
        update_badge()
        W5["steps"] = build_math_steps(EM, max(1, min(EM.N - 1, int(d5.get()))), int(m5.get()), mode5.get(), max(1, min(EM.N - 1, int(r5.get()))))
        lst5.delete(0, "end")
        for n, st_ in enumerate(W5["steps"], 1):
            lst5.insert("end", "%d. [%s] %s" % (n, st_["node"], st_["title"]))
        W5["i"] = min(W5["i"], len(W5["steps"]) - 1)
        draw5()

    def step5(dl):
        W5["i"] = max(0, min(len(W5["steps"]) - 1, W5["i"] + dl)); draw5()

    def tick5():
        if W5["auto"] is None:
            return
        if W5["i"] >= len(W5["steps"]) - 1:
            toggle5(); return
        step5(1); W5["auto"] = root.after(2600, tick5)

    def toggle5():
        if W5["auto"] is not None:
            root.after_cancel(W5["auto"]); W5["auto"] = None; play5.config(text="Play"); return
        if W5["i"] >= len(W5["steps"]) - 1:
            W5["i"] = 0; draw5()
        play5.config(text="Pause"); W5["auto"] = root.after(2600, tick5)

    rebuild5()

    # =============================================================== TAB 6 (the UWC protocol, M1-M12)
    tab6 = ttk.Frame(nb); nb.add(tab6, text="6  Protocol M1-M12")
    mode6 = tk.BooleanVar(value=False)
    scen6 = tk.StringVar(value=PROTO_SCENARIOS[0])
    W6 = {"ev": [], "sum": None, "i": 0, "auto": None, "cols": []}
    bar6 = ttk.Frame(tab6); bar6.pack(fill="x", padx=10, pady=(8, 2))
    ttk.Label(bar6, text="Scenario:").pack(side="left")
    cb6 = ttk.Combobox(bar6, values=PROTO_SCENARIOS, textvariable=scen6, width=40, state="readonly"); cb6.pack(side="left", padx=4)
    cb6.bind("<<ComboboxSelected>>", lambda e: rebuild6())
    ttk.Radiobutton(bar6, text="Paper-exact [18]", variable=mode6, value=False, command=lambda: rebuild6()).pack(side="left", padx=(12, 2))
    ttk.Radiobutton(bar6, text="Hardened (deviation)", variable=mode6, value=True, command=lambda: rebuild6()).pack(side="left", padx=2)
    ttk.Button(bar6, text="New run", command=lambda: rebuild6()).pack(side="left", padx=(12, 2))
    ttk.Button(bar6, text="Run attack suite", command=lambda: attacks6()).pack(side="left", padx=2)
    play6 = ttk.Button(bar6, text="Play", style="Accent.TButton", command=lambda: toggle6()); play6.pack(side="right", padx=2)
    ttk.Button(bar6, text="Next >", command=lambda: step6(1)).pack(side="right", padx=2)
    ttk.Button(bar6, text="< Back", command=lambda: step6(-1)).pack(side="right", padx=2)
    sum6 = tk.Label(tab6, text="", bg=C["white"], fg=C["navy"], font=("Segoe UI", 10, "bold"), anchor="w", padx=10, pady=4)
    sum6.pack(fill="x", padx=10, pady=(2, 4))
    body6 = ttk.Frame(tab6); body6.pack(fill="both", expand=True, padx=10, pady=(0, 8))
    lst6 = tk.Listbox(body6, width=30, font=("Segoe UI", 10), activestyle="none", exportselection=False, bg="white")
    lst6.pack(side="left", fill="y")
    lst6.bind("<<ListboxSelect>>", lambda e: (W6.__setitem__("i", lst6.curselection()[0]), draw6()) if lst6.curselection() else None)
    det6 = tk.Text(body6, width=58, font=("Consolas", 9), wrap="word", bg="#F8FAFB", relief="flat", state="disabled")
    det6.pack(side="right", fill="both", padx=(8, 0))
    for tg, col in (("h", C["navy"]), ("good", C["green"]), ("bad", C["red"]), ("dim", C["dgrey"])):
        det6.tag_configure(tg, foreground=col, font=("Consolas", 10 if tg == "h" else 9, "bold" if tg != "dim" else "normal"))
    seq6 = tk.Canvas(body6, bg=C["white"], highlightthickness=1, highlightbackground="#C9D2DA")
    seq6.pack(side="left", fill="both", expand=True, padx=(8, 0))
    seq6.bind("<Configure>", lambda e: draw6())
    KORD = {"UWS": 0, "SUB": 1, "B": 2, "SAT": 3, "BS": 4}

    def ev_title(e):
        k = e["kind"]
        if k == "message":
            p = e["pkt"]
            return "%-4s %s -> %s%s" % (p.label, p.src, p.dst, "" if e["ok"] else "  REJECTED")
        if k == "session":
            return "session %s <-> %s" % (e["a"], e["b"])
        if k == "timeout":
            return "%-4s %s -> %s  no reply" % (e["label"], e["src"], e["dst"])
        return "FALLBACK %s -> %s" % (e["src"], e["dst"])

    def draw6():
        seq6.delete("all")
        if not W6["ev"]:
            return
        w, h = max(seq6.winfo_width(), 500), max(seq6.winfo_height(), 400)
        cols = W6["cols"]
        xs = {n: 50 + (w - 100) * k / max(1, len(cols) - 1) for k, n in enumerate(cols)}
        top, row = 58, max(18, min(30, (h - 80) / max(1, len(W6["ev"]))))
        kinds = W6["sum"]["kinds"]
        for n in cols:
            seq6.create_rectangle(xs[n] - 44, 8, xs[n] + 44, 42, fill=C["lblue"], outline=C["blue"])
            seq6.create_text(xs[n], 25, text="%s\n(%s)" % (n, kinds[n]), font=("Segoe UI", 9, "bold"), justify="center")
            seq6.create_line(xs[n], 42, xs[n], h - 10, fill="#C9D2DA", dash=(4, 3))
        for j, e in enumerate(W6["ev"][:W6["i"] + 1]):
            y = top + j * row
            cur = j == W6["i"]
            k = e["kind"]
            if k == "message":
                p = e["pkt"]
                col = C["orange"] if cur else (C["dgrey"] if e["ok"] else C["red"])
                seq6.create_line(xs[p.src], y, xs[p.dst], y, arrow="last", width=3 if cur else 1.5, fill=col)
                eve = "  Eve reads it" if e["eve"] is not None else ""
                seq6.create_text((xs[p.src] + xs[p.dst]) / 2, y - 7, text="%s  %d bit%s" % (p.label, 8 * len(p.ct), eve),
                                 font=("Segoe UI", 8, "bold" if cur else "normal"), fill=C["red"] if eve else C["navy"])
            elif k == "session":
                a, b = sorted((xs[e["a"]], xs[e["b"]]))
                seq6.create_rectangle(a, y - 6, b, y + 6, fill=C["lgreen"], outline=C["green"], width=2 if cur else 1)
                seq6.create_text((a + b) / 2, y, text="session established", font=("Segoe UI", 8), fill=C["green"])
            elif k == "timeout":
                seq6.create_line(xs[e["src"]], y, xs[e["dst"]], y, arrow="last", dash=(6, 4), fill=C["red"], width=2)
                seq6.create_text(xs[e["dst"]], y - 8, text="X no reply", fill=C["red"], font=("Segoe UI", 8, "bold"))
            else:
                seq6.create_text(xs[e["src"]] + 6, y, anchor="w", text="FALLBACK: %s -> %s" % (e["after"], e["dst"]),
                                 fill=C["orange"], font=("Segoe UI", 9, "bold"))
        show6(W6["ev"][W6["i"]])
        lst6.selection_clear(0, "end"); lst6.selection_set(W6["i"]); lst6.see(W6["i"])

    def put6(text, tag=()):
        det6.insert("end", text + "\n", tag)

    def show6(e):
        det6.configure(state="normal"); det6.delete("1.0", "end")
        k = e["kind"]
        if k == "message":
            p = e["pkt"]
            put6("%s   %s -> %s   t = %.3f s" % (p.label, p.src, p.dst, e["t"]), "h")
            put6("PEECC-encrypted with %s's public key" % p.dst, "dim")
            put6("\nPlaintext fields (what %s puts in the message)" % p.src, "h")
            for f, v in p.fields.items():
                put6("  %-13s %s" % (f, v))
            bb = e["block"]
            nb_ = len(p.ct) // bb
            put6("\nOn the wire: %d block(s) x %d bit = %d bit   (paper-model size %d bit)"
                 % (nb_, 8 * bb, 8 * len(p.ct), e["model_bits"]), "h")
            put6("  points %s" % ("compressed: 02/03 || x (33 bytes each)" if bb < 128 else "x || y (64 bytes each, as in the paper)"),
                 "dim")
            for b in range(nb_):
                c = p.ct[bb * b:bb * (b + 1)]
                put6("  block %d  C1 %s..  C2 %s.." % (b + 1, c[:10].hex(), c[bb // 2:bb // 2 + 10].hex()))
            put6("\nReceiver %s checks" % p.dst, "h")
            for name, ok in e["checks"]:
                put6("  [%s] %s" % ("ok" if ok else "FAIL", name), "good" if ok else "bad")
            put6("  => %s" % ("ACCEPTED" if e["ok"] else "REJECTED: " + e["why"]), "good" if e["ok"] else "bad")
            put6("\nReceiver decrypts with its private key", "h")
            put6("  " + (e["plain"].hex() if e["plain"] is not None else "(rejected)"))
            put6("\nEve (no key): C2 - K_paper * Pub", "h")
            if e["eve"] is not None:
                put6("  reads " + e["eve"].hex(), "bad")
                put6("  = the plaintext: the paper's K is public, so this message is NOT confidential", "bad")
            else:
                put6("  cannot read it: K came from a secret random x (hardened mode)", "good")
        elif k == "session":
            put6("Session S_%s<->%s established" % (e["a"], e["b"]), "h")
            put6("\nThe initiator received its own nonce back (only the holder of the responder's private key can read "
                 "the request) and the timestamps were fresh: |TS_resp - TS_req| < dT.")
            if not mode6.get():
                put6("\nIn paper-exact mode this proof is void: anybody can read the request with the public K.", "bad")
        elif k == "timeout":
            put6("%s %s -> %s: no reply" % (e["label"], e["src"], e["dst"]), "h")
            put6("\n%s waited dT = %.2f s for the response; the peer is unresponsive." % (e["src"], e["wait"]))
        else:
            put6("Fallback (IoT Sec. IV-D)", "h")
            put6("\n%s gives up on %s and re-authenticates with its preregistered fallback peer %s, "
                 "with the same nonce and timestamp checks." % (e["src"], e["after"], e["dst"]))
        det6.configure(state="disabled")

    def rebuild6():
        update_badge()
        if W6["auto"] is not None:
            toggle6()
        sum6.config(text="running the protocol with peecc.dll ...", fg=C["navy"]); root.update_idletasks()
        try:
            ev, sm = build_protocol_events(mode6.get(), PROTO_SCENARIOS.index(scen6.get()))
        except (OSError, ImportError) as ex:
            sum6.config(text="Protocol library not available (%s). Build it with `make lib`." % ex, fg=C["red"])
            return
        names = []
        for e in ev:
            for n in ([e["pkt"].src, e["pkt"].dst] if e["kind"] == "message" else [e.get("src"), e.get("dst"), e.get("a"), e.get("b")]):
                if n and n not in names:
                    names.append(n)
        W6.update(ev=ev, sum=sm, i=0, cols=sorted(names, key=lambda n: (KORD[sm["kinds"][n]], names.index(n))))
        sum6.config(fg=C["green"] if sm["eve_read"] == 0 else C["red"], text=
                    "%s  |  %d messages, %d bit on the wire (paper model %d bit)  |  %.2f s simulated  |  %d sessions  |  "
                    "keyless Eve reads %d of %d messages" % ("authenticated" if sm["ok"] else "FAILED", sm["messages"], sm["wire_bits"],
                                                             sm["model_bits"], sm["seconds"], sm["sessions"], sm["eve_read"], sm["messages"]))
        lst6.delete(0, "end")
        for n, e in enumerate(ev, 1):
            lst6.insert("end", "%2d. %s" % (n, ev_title(e)))
        draw6()

    def attacks6():
        import simulate as SIM
        import protocol as P
        sum6.config(text="running 11 attacks on fresh networks ...", fg=C["navy"]); root.update_idletasks()
        res = SIM.attack_suite(P.Peecc(), mode6.get(), 1)
        det6.configure(state="normal"); det6.delete("1.0", "end")
        put6("Attack suite (%s)" % ("hardened" if mode6.get() else "paper-exact"), "h")
        for a in res:
            put6("\n%s" % a["name"], "h")
            put6("  %s - %s" % ("DETECTED" if a["detected"] else "NOT DETECTED", a["detail"]), "good" if a["detected"] else "bad")
        det6.configure(state="disabled")
        n = sum(a["detected"] for a in res)
        sum6.config(text="attack suite: %d of %d detected (details on the right)" % (n, len(res)),
                    fg=C["green"] if n == len(res) else C["red"])

    def step6(dl):
        if W6["ev"]:
            W6["i"] = max(0, min(len(W6["ev"]) - 1, W6["i"] + dl)); draw6()

    def tick6():
        if W6["auto"] is None:
            return
        if W6["i"] >= len(W6["ev"]) - 1:
            toggle6(); return
        step6(1); W6["auto"] = root.after(1800, tick6)

    def toggle6():
        if W6["auto"] is not None:
            root.after_cancel(W6["auto"]); W6["auto"] = None; play6.config(text="Play"); return
        if W6["i"] >= len(W6["ev"]) - 1:
            W6["i"] = 0; draw6()
        play6.config(text="Pause"); W6["auto"] = root.after(1800, tick6)

    # =============================================================== TAB 7 (results: claims and the charts behind them)
    tab7 = ttk.Frame(nb); nb.add(tab7, text="7  Results & charts")
    left7 = ttk.Frame(tab7); left7.pack(side="left", fill="y", padx=(10, 4), pady=8)
    ttk.Label(left7, text="Paper claims (select one to show its charts)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
    tc = ttk.Treeview(left7, columns=("c", "p", "a", "b"), show="headings", height=17, style="Compact.Treeview")
    for c, w, nm in (("c", 255, "Claim"), ("p", 62, "Paper"), ("a", 88, "paper-exact"), ("b", 88, "hardened")):
        tc.heading(c, text=nm); tc.column(c, width=w, anchor="w" if c == "c" else "center")
    for tg, col in (("PASS", C["green"]), ("FAIL", C["red"]), ("N.A.", C["dgrey"])):
        tc.tag_configure(tg, foreground=col)
    tc.pack(anchor="w")
    ttk.Label(left7, text="Charts shown (tick / untick)", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 2))
    show7 = {k: tk.BooleanVar(value=(k == "claims_scorecard")) for k, _ in RESULT_FIGS}
    for k, title in RESULT_FIGS:
        ttk.Checkbutton(left7, text=title, variable=show7[k], command=lambda: draw7()).pack(anchor="w")
    row7 = ttk.Frame(left7); row7.pack(anchor="w", pady=(8, 0))
    ttk.Button(row7, text="All", command=lambda: set7(k for k, _ in RESULT_FIGS)).pack(side="left", padx=(0, 4))
    ttk.Button(row7, text="None", command=lambda: set7(())).pack(side="left", padx=4)
    ttk.Button(row7, text="Redraw from saved results", command=lambda: regen7()).pack(side="left", padx=4)
    info7 = ttk.Label(left7, text="", wraplength=440, justify="left"); info7.pack(anchor="w", pady=(8, 0))
    right7 = ttk.Frame(tab7); right7.pack(side="left", fill="both", expand=True, padx=(4, 10), pady=8)
    cv7 = tk.Canvas(right7, bg=C["white"], highlightthickness=1, highlightbackground="#C9D2DA")
    sb7 = ttk.Scrollbar(right7, orient="vertical", command=cv7.yview)
    cv7.configure(yscrollcommand=sb7.set)
    sb7.pack(side="right", fill="y"); cv7.pack(side="left", fill="both", expand=True)
    cv7.bind("<MouseWheel>", lambda e: cv7.yview_scroll(int(-e.delta / 120), "units"))
    cv7.bind("<Configure>", lambda e: draw7())
    W7 = {"imgs": [], "claims": {}, "width": 0, "head": ""}
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

    def load_image(path, width):
        """PNG scaled to the canvas width (Pillow if available, otherwise Tk's integer subsample)."""
        try:
            from PIL import Image, ImageTk
            im = Image.open(path)
            if im.width > width:
                im = im.resize((width, int(im.height * width / im.width)), Image.LANCZOS)
            return ImageTk.PhotoImage(im)
        except ImportError:
            im = tk.PhotoImage(file=path)
            f = max(1, -(-im.width() // width))
            return im.subsample(f) if f > 1 else im

    def draw7():
        cv7.delete("all"); W7["imgs"] = []
        width = max(400, cv7.winfo_width() - 20)
        y = 10
        if W7["head"]:
            st_ = W7["head"].split("\n")
            col = C["green"] if st_[-1].endswith("PASS") else C["red"] if st_[-1].endswith("FAIL") else C["dgrey"]
            t = cv7.create_text(14, y + 6, anchor="nw", text=W7["head"], font=("Segoe UI", 10), fill="#222", width=width - 20)
            bb = cv7.bbox(t)
            cv7.tag_lower(cv7.create_rectangle(8, y, width + 10, bb[3] + 6, fill="#F3F5F7", outline=col, width=2), t)
            y = bb[3] + 18
        chosen = [(k, t) for k, t in RESULT_FIGS if show7[k].get()]
        if not chosen:
            cv7.create_text(20, 20, anchor="nw", text="No chart selected: tick a chart on the left or select a claim.",
                            font=("Segoe UI", 11), fill=C["dgrey"])
        for k, title in chosen:
            path = os.path.join(results_dir, k + ".png")
            cv7.create_text(10, y, anchor="nw", text=title, font=("Segoe UI", 11, "bold"), fill=C["navy"])
            y += 24
            if not os.path.exists(path):
                cv7.create_text(10, y, anchor="nw", fill=C["red"], font=("Segoe UI", 10),
                                text="results/%s.png not found: run  python simulate.py --all  (and --all --hardened)" % k)
                y += 30; continue
            img = load_image(path, width)
            W7["imgs"].append(img)
            cv7.create_image(10, y, anchor="nw", image=img)
            y += img.height() + 18
        cv7.configure(scrollregion=(0, 0, width + 20, y))

    def set7(keys):
        keys = set(keys)
        for k, v in show7.items():
            v.set(k in keys)
        cv7.yview_moveto(0); draw7()

    def fill7():
        for iid in tc.get_children():
            tc.delete(iid)
        try:
            import simulate as SIM
            M = SIM.load_modes()
        except ImportError:
            M = {}
        rows = {}
        for mode, m in M.items():
            for r in m.get("claims", []):
                rows.setdefault(r["claim"], dict(paper=r["paper"], status=r["status"]))[mode] = r["measured"]
                if r["status"] == "FAIL":
                    rows[r["claim"]]["status"] = "FAIL"
        W7["claims"] = rows
        for name, r in rows.items():
            short_ = lambda s: (s or "-").split(" (")[0][:12]
            tc.insert("", "end", iid=name, values=(name, r["paper"], short_(r.get("paper-exact")), short_(r.get("hardened"))),
                      tags=(r["status"],))
        info7.config(text=("Green = met, red = not met in at least one mode (modes found: %s)." % ", ".join(M)) if M else
                     "No saved results yet: run  python simulate.py --all  and  python simulate.py --all --hardened.")

    def on_claim(e):
        sel = tc.selection()
        if not sel:
            return
        name = sel[0]
        r = W7["claims"].get(name, {})
        W7["head"] = ("%s\npaper: %s     |     paper-exact run: %s     |     hardened run: %s\nresult: %s"
                      % (name, r.get("paper"), r.get("paper-exact", "-"), r.get("hardened", "-"), r.get("status")))
        set7(claim_figures(name))
    tc.bind("<<TreeviewSelect>>", on_claim)

    def regen7():
        import simulate as SIM
        import protocol as P
        info7.config(text="redrawing figures ..."); root.update_idletasks()
        try:
            SIM.figures(P.Peecc())
        except OSError as ex:
            info7.config(text="peecc.dll not available (%s): build it with make lib" % ex); return
        fill7(); draw7()

    built7 = {"done": False}
    mode_src.update({tab2: mode2, tab5: mode5, tab6: mode6})
    built6 = {"done": False}

    def on_tab(e):
        cur = nb.nametowidget(nb.select())
        if cur is tab6 and not built6["done"]:
            built6["done"] = True; rebuild6()
        if cur is tab7 and not built7["done"]:
            built7["done"] = True; fill7(); draw7()
    nb.bind("<<NotebookTabChanged>>", lambda e: (update_badge(), on_tab(e)), add="+")

    update_badge()
    def key_next(delta):
        cur = nb.nametowidget(nb.select())
        if cur is tab1:
            (nxt if delta > 0 else prv)()
        elif cur is tab2:
            step2(delta)
        elif cur is tab5:
            step5(delta)
        elif cur is tab6:
            step6(delta)
    root.bind("<Right>", lambda e: key_next(1))
    root.bind("<Left>", lambda e: key_next(-1))
    root.after(300, run)

    if "--shots" in sys.argv:                           # developer aid: screenshots of some steps and tabs
        from PIL import ImageGrab
        root.attributes("-topmost", True); root.lift()
        out = sys.argv[sys.argv.index("--shots") + 1]

        def grab(name):
            root.update(); root.update_idletasks()
            f = 1.0                                   # process is DPI aware in --shots mode
            ImageGrab.grab(bbox=(int(root.winfo_rootx() * f), int(root.winfo_rooty() * f),
                                 int((root.winfo_rootx() + root.winfo_width()) * f),
                                 int((root.winfo_rooty() + root.winfo_height()) * f))).save("%s/%s.png" % (out, name))

        def seq(k=0):
            plan = sys.argv[sys.argv.index("--shots") + 2].split(",") if len(sys.argv) > sys.argv.index("--shots") + 2 \
                else ["p11", "m8", "imp", "met"]
            if k >= len(plan):
                root.destroy(); return
            n = plan[k]
            if n.startswith("res"):                     # res<i>: tab 7 with claim row i selected
                nb.select(tab7); root.update()
                rows_ = tc.get_children()
                if rows_:
                    tc.selection_set(rows_[int(n[3:]) - 1])
            elif n.startswith("proto"):                 # proto<i>[h]: tab 6, event i, h = hardened
                nb.select(tab6); mode6.set(n.endswith("h")); rebuild6()
                W6["i"] = int(n[5:].rstrip("h")) - 1; draw6()
            elif n.startswith("p"):
                nb.select(tab1)
                if n.endswith("h") and not improved_var.get():          # p<i>h: improved mode
                    improved_var.set(True); run()
                show_step(int(n[1:].rstrip("h")) - 1)
            elif n.startswith("m") and n != "met":
                nb.select(tab5); W5["i"] = int(n[1:]) - 1; draw5()
            elif n == "met":
                nb.select(tab4); n4.set(6); start_met()
            else:
                nb.select(tab3); n_var.set(5); start_bench()
            root.after(9000 if n in ("imp", "met") else 1800, lambda: (grab(n), seq(k + 1)))
        root.after(1500, seq)
    root.mainloop()


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        run_gui()
