"""simulate.py - simulation, attacks, metrics and logging for the UWC protocol (IoT Sec. IV and VI) on PEECC [18].

    python simulate.py --demo         trace of every message of one full authentication UWS -> SUB -> B -> SAT -> BS
    python simulate.py --attacks      replay, delay, impersonation, registration, revocation, K-public eavesdropping
    python simulate.py --fallback     IoT Sec. IV-D: unresponsive buoy, delayed satellite, mobile node
    python simulate.py --scale        authentication delay vs node count (10-200) and depth (2-5)
    python simulate.py --all          everything above + metrics, claims table, charts, figures and Scyther
    python simulate.py --figures      redraw the claim / improvement / performance figures from saved results
    add --hardened                    hardened PEECC (deviation from [18]); default is paper-exact

Outputs: logs/run_<timestamp>.log, results/metrics.json, results/metrics.csv, results/*.png, results/scyther_output.txt.
Every number is computed from the messages actually sent; paper values appear only as the "claim" column.
"""
import argparse
import csv
import json
import logging
import os
import random
import re
import secrets
import subprocess
import sys
import time

import protocol as P

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS, LOGS = os.path.join(HERE, "results"), os.path.join(HERE, "logs")
SCYTHER = os.path.join(HERE, "scyther", "scyther-w32-v1.3.0", "Scyther", "scyther-w32.exe")
log = logging.getLogger("uwc")

# Paper values (IoT Sec. VI), used only for comparison.
PAPER = dict(total_bits=2112, baseline_bits=(3008, 3216), reduction=(30, 34), comp_ms={"UWS": 0.4, "BS": 0.4, "SUB": 0.5,
             "B": 0.5, "SAT": 0.5}, energy_uj={"ecc": 24.0, "hash": 6.0, "aes": 3.2}, uws_energy_uj=48.8,
             uws_ops={"ecc": 1, "hash": 2, "enc": 2, "dec": 2}, reauth_ms=1.0, storage_bytes=250, overhead_5d=1.3)
FIELD_BITS = dict(id=64, nonce=64, ts=8, hash=160, point=512)      # IoT Sec. VI-A


def mode_name(hardened):
    return ("HARDENED (deviation from [18]: random pentatope input x, K mod N, point validation, compressed points)" if hardened
            else "paper-exact [18] (x = B_x, K public)")


def setup_logging():
    os.makedirs(LOGS, exist_ok=True)
    path = os.path.join(LOGS, "run_%s.log" % time.strftime("%Y%m%d_%H%M%S"))
    log.setLevel(logging.INFO)
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    log.addHandler(fh)
    return path


def console(on):
    """Protocol log lines also go to the console unless the run is quiet."""
    if on and not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler) for h in log.handlers):
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter("    log %(message)s"))
        log.addHandler(sh)


def section(title):
    print("\n" + "=" * 100 + "\n" + title + "\n" + "=" * 100)


def new_network(lib, hardened, seed):
    net = P.build_fig1(lib, hardened, seed)
    net.initialize()
    P.register_all(net)
    return net


def run_chain(net, uws_list, rng, upward=True):
    """IoT Sec. IV-C: each UWS authenticates with its SUB (M1-M3); then SUB -> B -> SAT -> BS (M4-M12) carrying
    the aggregated ENV, Alerts, GPS and LOGS. Returns {hop: (I, R, ok, seconds)}."""
    out = {}
    sub = net.up[uws_list[0]][0]
    for u in uws_list:
        payload, fields = P.data_payload(1, P.sample_env(rng))
        ok, why, dt = net.authenticate_hop(u, sub, P.HOP_LABELS[1], payload, fields)
        out[(u, sub)] = (ok, dt)
    if not upward:
        return out
    env = P.aggregate_env(net.nodes[sub].env_in)
    node, hop = sub, 2
    while node != "BS":
        parent = net.up[node][0]
        payload, fields = P.data_payload(hop, env, b"jamming:none spoof:none", (12.9716, 77.5946), b"fw=1.2 batt=87%")
        peer, ok, dt = net.authenticate_with_fallback(node, parent, P.HOP_LABELS[hop], payload, fields)
        out[(node, peer or parent)] = (ok, dt)
        if not ok:
            break
        node, hop = peer, hop + 1
    return out


# ============================================================================= --demo
def print_trace(kind, ev):
    if kind == "message":
        pkt = ev["pkt"]
        ct = pkt.ct
        bb = ev["block"]
        print("\n[%s] %s -> %s   t = %.3f s   %d block(s) x %d bit = %d bit on the wire"
              % (pkt.label, pkt.src, pkt.dst, ev["t"], len(ct) // bb, 8 * bb, 8 * len(ct)))
        for k, v in pkt.fields.items():
            print("      plaintext %-14s %s" % (k, v))
        print("      ciphertext C1 = %s..  C2 = %s..  (block 1, %s)"
              % (ct[:9].hex(), ct[bb // 2:bb // 2 + 9].hex(), "compressed: 02/03 || x" if bb < 128 else "x || y"))
        for name, ok in ev["checks"]:
            print("      check  [%s] %s" % ("ok" if ok else "FAIL", name))
        print("      result %s" % ("ACCEPTED" if ev["ok"] else "REJECTED: " + ev["why"]))
    elif kind == "session":
        print("      >>> session S_%s<->%s established at t = %.3f s" % (ev["a"], ev["b"], ev["t"]))
    elif kind == "timeout":
        print("\n[%s] %s -> %s   no response, waited dT = %.2f s" % (ev["label"], ev["src"], ev["dst"], ev["wait"]))
    elif kind == "fallback":
        print("\n>>> FALLBACK: %s switches from %s to preregistered peer %s" % (ev["src"], ev["after"], ev["dst"]))


def demo(lib, hardened, seed):
    section("DEMO  (mode: %s)" % mode_name(hardened))
    net = P.build_fig1(lib, hardened, seed)
    print("Topology of IoT Fig. 1: %d entities, primary path %s" % (len(net.nodes), " -> ".join(P.path_to_bs(net, "S1"))))
    net.initialize()
    print("Initialization (IoT IV-A): every entity has PK, PU = PK*B and ID = H(PU || E || serial); e.g. S1 ID = %s"
          % net.nodes["S1"].ID.hex())
    P.register_all(net)
    print("Registration (IoT IV-B): %d registrations on primary and fallback links, all VALID"
          % sum(len(e.R) for e in net.nodes.values()))
    print("\nMutual authentication (IoT IV-C): S1, S2, S3 -> SB1 (M1-M3), then SB1 -> B1 -> SAT1 -> BS (M4-M12)")
    net.trace = print_trace
    t0 = net.clock.now
    res = run_chain(net, ["S1", "S2", "S3"], random.Random(seed))
    net.trace = None
    print("\nAll hops authenticated: %s;  sessions created: %d;  simulated time %.3f s"
          % (all(ok for ok, _ in res.values()), net.sessions_created, net.clock.now - t0))
    return net


# ============================================================================= --attacks
def capture_request(net, I, R, label="M1"):
    """Honest initiator builds a request; returns the packet and its nonce/TS (not yet delivered)."""
    pkt, nonce, ts = net.make_request(I, R, label)
    net.transmit(pkt)
    return pkt, nonce, ts


def attack_suite(lib, hardened, seed):
    """Each attack runs on a fresh network. Returns a list of dicts (name, detected, detail)."""
    res = []

    def record(name, detected, detail):
        res.append(dict(name=name, detected=bool(detected), detail=detail))
        log.info("[ATTACK] %-36s %s - %s", name, "DETECTED" if detected else "NOT DETECTED", detail)

    # 1 replay: the same M1 again, within dT
    net = new_network(lib, hardened, seed)
    pkt, nonce, ts = capture_request(net, "S1", "SB1")
    net.handle_request("SB1", pkt)
    net.clock.now += 0.3
    ok, why, _, _ = net.handle_request("SB1", pkt)
    record("replay of M1 (within dT)", not ok, why)

    # 2 delay injection: hold M1 for 4 s (> dT, < 12.8 s wrap)
    net = new_network(lib, hardened, seed)
    pkt, _, _ = capture_request(net, "S1", "SB1")
    net.clock.now += 4.0
    ok, why, _, _ = net.handle_request("SB1", pkt)
    record("delay injection (M1 held 4 s)", not ok, why)

    # 3 delay injection by exactly one 8-bit timestamp period
    net = new_network(lib, hardened, seed)
    pkt, _, _ = capture_request(net, "S1", "SB1")
    net.clock.now += P.TS_MOD * P.TICK
    ok, why, _, _ = net.handle_request("SB1", pkt)
    record("delay injection (held 12.8 s, TS wraps)", not ok,
           why if not ok else "accepted: 8-bit TS wrapped and the nonce was never used (paper gap)")

    # 4 responder impersonation: Mallory answers M1 instead of SB1, using her own (wrong) private key
    net = new_network(lib, hardened, seed)
    m_pk, _ = lib.keygen()
    pkt, nonce, ts = capture_request(net, "S1", "SB1")
    learned = lib.decrypt(pkt.ct, m_pk, net.mode)            # wrong key
    how = "own key: %s" % ("read" if learned else "cannot decrypt")
    if learned is None:
        learned = lib.eavesdrop(pkt.ct, net.nodes["SB1"].PU, net.mode)  # K-public trick
        how += "; K-public: %s" % ("read the nonce" if learned else "failed")
    guess = learned[P.ID_BYTES:-1] if learned else secrets.token_bytes(P.NONCE_BYTES)
    forged = P.Packet("M2", "SB1", "S1", lib.encrypt(net.nodes["SB1"].ID + guess + bytes([P.ts8(net.clock.now)]),
                                                     net.nodes["S1"].PU, net.mode))
    net.transmit(forged)
    ok, why, _ = net.handle_response("S1", "SB1", forged, nonce, ts)
    record("impersonate SUB to UWS (wrong key)", not ok, "%s; S1: %s" % (how, why))

    # 5 initiator impersonation: Mallory claims to be S1 and injects sensor data (M1 carries no proof of PK_S1)
    net = new_network(lib, hardened, seed)
    s1, sb1 = net.nodes["S1"], net.nodes["SB1"]
    plain = s1.ID + secrets.token_bytes(P.NONCE_BYTES) + bytes([P.ts8(net.clock.now)])
    fake = P.Packet("M1", "S1", "SB1", lib.encrypt(plain, sb1.PU, net.mode))
    net.transmit(fake)
    ok1, why1, _, _ = net.handle_request("SB1", fake)
    if ok1:
        net.create_session("SB1", "S1", "responder")
    env = {"Temp": 99.0, "Press": 0.0, "CurrVel": 0.0, "Sal": 0.0}
    payload, _ = P.data_payload(1, env)
    fake3 = P.Packet("M3", "S1", "SB1", lib.encrypt(sb1.ID + payload + bytes([P.ts8(net.clock.now)]), sb1.PU, net.mode))
    net.transmit(fake3)
    ok3, why3, _, _ = net.handle_data("SB1", fake3)
    record("impersonate UWS to SUB (inject M1+M3)", not (ok1 and ok3),
           "M1 %s, fake M3 %s%s" % ("accepted" if ok1 else "rejected", "accepted" if ok3 else "rejected",
                                    ": no proof of PK_UWS in M1 (protocol gap)" if ok1 and ok3 else ""))

    # 6 tampered registration: PU changed in transit
    net = P.build_fig1(lib, hardened, seed); net.initialize()
    rid, pu, v = net.nodes["S1"].registration_message()
    st = net.register("S1", "SB1", (rid, net.nodes["S2"].PU, v))
    record("tampered registration (PU swapped)", st != "VALID", "status " + st)

    # 7 duplicate RID
    st1 = net.register("S1", "SB1")
    st2 = net.register("S1", "SB1")
    record("duplicate RID", st2 == "DUPLICATE", "first %s, second %s" % (st1, st2))

    # 8 rogue registration: Mallory's own key pair with a correct v
    _, m_pu = lib.keygen()
    m_rid = P.H(b"mallory", m_pu)
    st = net.register("S2", "SB1", (m_rid, m_pu, P.H(m_rid, m_pu)))
    record("rogue registration (own key, valid v)", st != "VALID", "status %s (directory check, IoT IV-E-3)" % st)

    # 9 revoked node + forged revocation list
    net = new_network(lib, hardened, seed)
    ids, tag = net.issue_revocation(["S7"])
    net.broadcast_revocation(ids, tag)
    pkt, _, _ = capture_request(net, "S7", "SB3")
    ok, why, _, _ = net.handle_request("SB3", pkt)
    record("revoked node S7 authenticates", not ok, why)
    bad_ids, _ = net.issue_revocation(["SB1"])
    accepted = net.broadcast_revocation(bad_ids, secrets.token_bytes(32))
    record("forged revocation list (revoke SB1)", not accepted, "tag check " + ("passed" if accepted else "failed"))

    # 10 K-public eavesdropping on a full authentication (all 12 messages)
    net = new_network(lib, hardened, seed)
    sent = []
    net.trace = lambda kind, ev: sent.append(ev["pkt"]) if kind == "message" else None
    run_chain(net, ["S1"], random.Random(seed))
    net.trace = None
    read = sum(1 for p in sent if lib.eavesdrop(p.ct, net.nodes[p.dst].PU, net.mode) is not None)
    record("K-public eavesdropping (M1-M12)", read == 0, "keyless attacker read %d of %d messages" % (read, len(sent)))
    return res


def attacks(lib, seed):
    section("ATTACKS  (each run in both modes; paper-exact = [18], hardened = deviation)")
    both = {h: attack_suite(lib, h, seed) for h in (False, True)}
    print("%-40s %-22s %-22s" % ("attack", "paper-exact", "hardened"))
    for a, b in zip(both[False], both[True]):
        print("%-40s %-22s %-22s" % (a["name"], "detected" if a["detected"] else "NOT DETECTED",
                                     "detected" if b["detected"] else "NOT DETECTED"))
    for h in (False, True):
        print("\n%s:" % mode_name(h))
        for a in both[h]:
            print("  %-40s %s" % (a["name"], a["detail"]))
    return both


# ============================================================================= --fallback
def fallback(lib, hardened, seed):
    section("FALLBACK  (IoT Sec. IV-D, mode: %s)" % mode_name(hardened))
    out = {}
    rng = random.Random(seed)

    net = new_network(lib, hardened, seed)
    net.trace = print_trace
    net.nodes["B1"].alive = False
    print("Scenario 1: buoy B1 is unresponsive; SB1 must re-authenticate via its fallback buoy")
    payload, fields = P.data_payload(2, P.sample_env(rng), b"none")
    peer, ok, dt = net.authenticate_with_fallback("SB1", "B1", P.HOP_LABELS[2], payload, fields)
    out["buoy_down"] = dict(peer=peer, ok=ok, seconds=dt)
    print("\n=> SB1 authenticated with %s: %s, fallback time %.3f s" % (peer, ok, dt))

    net = new_network(lib, hardened, seed)
    net.trace = print_trace
    net.nodes["SAT1"].respond_delay = 4.0
    print("\nScenario 2: satellite SAT1 answers 4 s late; B1 rejects the stale response and routes to its fallback SAT")
    payload, fields = P.data_payload(3, P.sample_env(rng), b"none", (12.97, 77.59))
    peer, ok, dt = net.authenticate_with_fallback("B1", "SAT1", P.HOP_LABELS[3], payload, fields)
    out["sat_delayed"] = dict(peer=peer, ok=ok, seconds=dt)
    print("\n=> B1 authenticated with %s: %s, fallback time %.3f s" % (peer, ok, dt))

    net = new_network(lib, hardened, seed)
    net.trace = print_trace
    s1 = net.nodes["S1"]
    new_sub = s1.fallback["SUB"][0]
    print("\nScenario 3: mobile node S1 moves into the range of %s and re-authenticates with M1-M3" % new_sub)
    cpu0, t0 = sum(net.nodes[n].cpu_ms for n in ("S1", new_sub)), net.clock.now
    payload, fields = P.data_payload(1, P.sample_env(rng))
    ok, why, dt = net.authenticate_hop("S1", new_sub, P.HOP_LABELS[1], payload, fields)
    cpu = sum(net.nodes[n].cpu_ms for n in ("S1", new_sub)) - cpu0
    out["mobile_reauth"] = dict(peer=new_sub, ok=ok, seconds=dt, compute_ms=cpu)
    print("\n=> re-authentication %s: total %.3f s (computation %.3f ms, rest is acoustic transmission)"
          % ("succeeded" if ok else "FAILED", dt, cpu))
    return out


# ============================================================================= --scale
def build_tree(lib, hardened, n_nodes, depth, seed, fanout=None):
    """Hierarchical tree (IoT Sec. VI-A): `depth` levels ending at BS. Either n_nodes with level sizes growing by
    ~2.5x towards the leaves, or (fanout given) exactly `fanout` children per parent."""
    kinds = {2: ["BS", "UWS"], 3: ["BS", "SUB", "UWS"], 4: ["BS", "B", "SUB", "UWS"],
             5: ["BS", "SAT", "B", "SUB", "UWS"]}[depth]
    if fanout:
        sizes = [fanout ** l for l in range(depth)]
    else:
        w = [2.5 ** l for l in range(1, depth)]
        sizes = [1] + [max(1, round((n_nodes - 1) * x / sum(w))) for x in w]
        sizes[-1] = max(1, n_nodes - sum(sizes[:-1]))
    net = P.Network(lib, hardened, seed)
    levels = []
    for l, (k, s) in enumerate(zip(kinds, sizes)):
        levels.append([net.add("%s_%d_%d" % (k, l, i), k).name for i in range(s)])
    net.up = {}
    for l in range(1, depth):
        for i, c in enumerate(levels[l]):
            net.up[c] = [levels[l - 1][i % len(levels[l - 1])]]
            net.link(c, net.up[c][0])
    net.initialize()
    for c, (p,) in net.up.items():
        net.register_pair(c, p)
    return net, levels


def scale_run(lib, hardened, n_nodes, depth, seed, series, fanout=None):
    """Every child authenticates with its parent (real crypto). A parent's modem serves its children one after the
    other; a node starts its own upward hop after all its children (aggregation). Returns latencies in seconds."""
    net, levels = build_tree(lib, hardened, n_nodes, depth, seed, fanout)
    n_nodes = len(net.nodes)
    rng = random.Random(seed)
    hop_of = {"UWS": 1, "SUB": 2, "B": 3, "SAT": 4}
    ready, free, done_top = {}, {}, {}
    for l in range(depth - 1, 0, -1):
        for c in levels[l]:
            p = net.up[c][0]
            start = max(ready.get(c, 0.0), free.get(p, 0.0))
            net.clock.now = start
            hop = hop_of[net.nodes[c].kind]
            payload, fields = P.data_payload(hop, P.sample_env(rng), b"none", (0.0, 0.0), b"ok")
            ok, why, _ = net.authenticate_hop(c, p, P.HOP_LABELS[hop], payload, fields)
            end = net.clock.now
            free[p] = end
            ready[p] = max(ready.get(p, 0.0), end)
            if l == 1:
                done_top[c] = end
    leaves = levels[-1]

    def top(u):
        while net.up[u][0] != "BS_0_0":
            u = net.up[u][0]
        return u
    per_leaf = [done_top[top(u)] for u in leaves]
    return dict(series=series, nodes=n_nodes, depth=depth, end_to_end=ready["BS_0_0"],
                mean_leaf=sum(per_leaf) / len(per_leaf), messages=len(net.messages),
                bits=8 * sum(m["bytes"] for m in net.messages))


def scale(lib, hardened, seed):
    """Three series: node count 10-200 at depth 5; depth 2-5 at a fixed 100 nodes (shallow trees then have a large
    fan-in per parent); depth 2-5 at a fixed fan-out of 3 children per parent (4 to 121 nodes)."""
    section("SCALE  (IoT Sec. VI-A: 10-200 nodes, 2-5 levels, mode: %s)" % mode_name(hardened))
    rows = [scale_run(lib, hardened, n, 5, seed, "nodes") for n in (10, 25, 50, 100, 200)]
    rows += [scale_run(lib, hardened, 100, d, seed, "depth, 100 nodes") for d in (2, 3, 4, 5)]
    rows += [scale_run(lib, hardened, 0, d, seed, "depth, fan-out 3", fanout=3) for d in (2, 3, 4, 5)]
    print("%-18s %6s %6s %10s %14s %17s %11s" % ("series", "nodes", "depth", "messages", "on-wire bits", "mean leaf->BS s",
                                                 "all done s"))
    for r in rows:
        print("%-18s %6d %6d %10d %14d %17.2f %11.2f" % (r["series"], r["nodes"], r["depth"], r["messages"], r["bits"],
                                                        r["mean_leaf"], r["end_to_end"]))
    return rows


# ============================================================================= metrics
def model_bits(msg):
    """Paper model (IoT Sec. VI-A): plaintext fields only, 64-bit ID/nonce, 8-bit TS; data payload as encoded here."""
    f = msg["fields"]
    if msg["label"] in ("M1", "M2", "M4", "M5", "M7", "M8", "M10", "M11"):
        return FIELD_BITS["id"] + FIELD_BITS["nonce"] + FIELD_BITS["ts"]
    payload = 128 + (8 * (1 + len(f["Alerts"])) if "Alerts" in f else 0) + (64 if "GPS" in f else 0) \
        + (8 * (1 + len(f["LOGS"])) if "LOGS" in f else 0)
    return FIELD_BITS["id"] + payload + FIELD_BITS["ts"]


def chain_metrics(lib, hardened, seed):
    """One full authentication on a 5-entity chain UWS-SUB-B-SAT-BS: everything per entity, from the real run."""
    net = P.Network(lib, hardened, seed)
    for n, k in (("UWS", "UWS"), ("SUB", "SUB"), ("B", "B"), ("SAT", "SAT"), ("BS", "BS")):
        net.add(n, k)
    net.up = {"UWS": ["SUB"], "SUB": ["B"], "B": ["SAT"], "SAT": ["BS"]}
    for c, (p,) in net.up.items():
        net.link(c, p)
    net.initialize()
    for c, (p,) in net.up.items():
        net.register_pair(c, p)
    reg_bits = 8 * (P.HASH_BYTES * 2 + 64)
    t0 = net.clock.now
    res = run_chain(net, ["UWS"], random.Random(seed))
    latency = net.clock.now - t0
    msgs = net.messages
    per_hop = {}
    for m in msgs:
        h = "-".join(sorted(m["hop"]))
        per_hop.setdefault(h, dict(prop_s=m["prop"], tx_s=0.0))["tx_s"] += m["tx"]
    model = sum(model_bits(m) for m in msgs)
    auth_only = sum(model_bits(m) for m in msgs if m["label"] not in ("M3", "M6", "M9", "M12"))
    wire = 8 * sum(m["bytes"] for m in msgs)
    ent = {}
    for e in net.nodes.values():
        o = e.ops
        ent[e.name] = dict(ecc_mul=o["ecc_mul"], ecc_bits=o["ecc_bits"], hash=o["hash"], enc=o["enc"], dec=o["dec"],
                           compute_ms=round(e.cpu_ms, 3), energy_uj=round(e.energy_uj(), 1),
                           energy_flat_uj=round(e.energy_uj(flat=True), 1),
                           storage_bytes=e.storage_bytes(), sessions=len(e.sessions))
    return dict(ok=all(ok for ok, _ in res.values()), latency_s=latency, messages=len(msgs),
                block_bits=8 * net.block_bytes, compressed=net.compressed, k_bits=net.k_bits,
                per_message=[dict(label=m["label"], src=m["src"], dst=m["dst"], model_bits=model_bits(m), wire_bits=8 * m["bytes"])
                             for m in msgs],
                model_bits=model, auth_only_bits=auth_only, wire_bits=wire, registration_bits_each=reg_bits,
                model_tx_ms=1000 * model / P.BITRATE, wire_tx_ms=1000 * wire / P.BITRATE, per_hop=per_hop, entities=ent,
                sessions=net.sessions_created)


def linear_r2(xs, ys):
    n = len(xs); mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs); sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    b = sxy / sxx; a = my - b * mx
    ss_res = sum((y - a - b * x) ** 2 for x, y in zip(xs, ys)); ss_tot = sum((y - my) ** 2 for y in ys)
    return a, b, 1 - ss_res / ss_tot if ss_tot else 1.0


def scyther():
    """Run the local Scyther binary on uwc_protocol.spdl; save the output; count claim results."""
    if not os.path.exists(SCYTHER):
        return None
    t0 = time.time()
    run = subprocess.run([SCYTHER, "--max-runs=5", os.path.join(HERE, "uwc_protocol.spdl")], capture_output=True,
                         text=True, timeout=600)
    out = re.sub(r"\x1b\[[0-9;]*m", "", run.stdout + run.stderr)
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "scyther_output.txt"), "w", encoding="utf-8") as f:
        f.write(out)
    claims = [l.split("\t") for l in out.splitlines() if l.startswith("claim")]
    rows = [dict(protocol=c[1], claim=c[2], param=c[3], result=c[4].strip(), note=c[5] if len(c) > 5 else "") for c in claims]
    return dict(seconds=time.time() - t0, claims=rows, ok=sum(r["result"] == "Ok" for r in rows),
                fail=sum(r["result"] == "Fail" for r in rows))


def claims_table(m):
    """Paper claim, measured value, PASS/FAIL/N.A. and the reason."""
    ch, rows = m["chain"], []

    def add(claim, paper, measured, status, reason):
        rows.append(dict(claim=claim, paper=paper, measured=measured, status=status, reason=reason))

    lo, hi = PAPER["baseline_bits"]
    red = (100 * (1 - PAPER["total_bits"] / lo), 100 * (1 - PAPER["total_bits"] / hi))
    add("Total communication cost (paper model)", "2112 bit", "%d bit (handshakes only: %d)" % (ch["model_bits"], ch["auth_only_bits"]),
        "PASS" if ch["model_bits"] == 2112 else "FAIL",
        "derived candidate 4 x (136+136+256); our M1/M2-type messages are 136 bit each as assumed, but the paper does "
        "not give data-message sizes, so our M3/M6/M9/M12 encodings differ")
    add("30-34% reduction vs 3008-3216 bit", "30-34 %", "%.1f-%.1f %% (paper's own numbers); ours vs baselines %.1f-%.1f %%"
        % (red[0], red[1], 100 * (1 - ch["model_bits"] / lo), 100 * (1 - ch["model_bits"] / hi)),
        "PASS" if 29.5 <= red[0] and red[1] <= 34.5 else "FAIL", "arithmetic from the paper's figures; 29.8 % rounds to 30 %")
    add("Transmission time of 2112 bit at 10 kbps", "211 ms", "%.0f ms model, %.0f ms on the wire" % (ch["model_tx_ms"], ch["wire_tx_ms"]),
        "FAIL" if ch["wire_bits"] > 2112 else "PASS",
        "the paper counts plaintext fields; every PEECC block on the wire is %d bit (C1, C2%s), %d bit in total"
        % (ch["block_bits"], ", compressed points" if ch["compressed"] else ", 512-bit points as in the paper", ch["wire_bits"]))
    for k in ("UWS", "SUB", "B", "SAT", "BS"):
        ms = ch["entities"][k]["compute_ms"]
        add("Computation per entity: %s" % k, "%.3f ms" % PAPER["comp_ms"][k], "%.3f ms (measured, incl. keygen)" % ms,
            "PASS" if ms <= PAPER["comp_ms"][k] else "FAIL",
            "measured C code on this PC; one secp256r1 scalar multiplication alone takes ~0.8-1 ms"
            + ("; paper-exact K has 2029 bits" if not m["hardened"] else ""))
    u = ch["entities"]["UWS"]
    add("UWS energy per authentication", "48.8 uJ", "%.1f uJ (%d ECC mult, %d hash, %d enc, %d dec; flat model %.1f uJ)"
        % (u["energy_uj"], u["ecc_mul"], u["hash"], u["enc"], u["dec"], u["energy_flat_uj"]),
        "PASS" if u["energy_uj"] <= 48.8 else "FAIL",
        "paper's per-operation energies, ECC charged per 256 scalar bits (K has %d bits in this mode); PEECC needs 2 ECC "
        "multiplications per encrypted block and 1 per decryption, the paper counts 1 ECC and charges encryption at the "
        "AES rate" % ch["k_bits"])
    fb = m.get("fallback", {}).get("mobile_reauth")
    if fb:
        add("Mobile re-authentication (M1-M3)", "< 1 ms", "%.3f ms computation, %.3f s incl. acoustic links" % (fb["compute_ms"], fb["seconds"]),
            "PASS" if fb["compute_ms"] < 1 else "FAIL", "computation measured; the paper's figure ignores propagation and transmission")
    st = max(e["storage_bytes"] for k, e in m["fig1_storage"].items() if k.startswith("S") and not k.startswith("SAT") and not k.startswith("SB"))
    add("Registry storage of a UWS (< 10 peers)", "< 250 B", "%d B (20 B per RID)" % st, "PASS" if st < 250 else "FAIL", "")
    att = m.get("attacks")
    if att:
        for name, rows_ in att.items():
            det = sum(a["detected"] for a in rows_)
            add("Attacks detected (%s)" % name, "all", "%d of %d" % (det, len(rows_)), "PASS" if det == len(rows_) else "FAIL",
                "; ".join(a["name"] for a in rows_ if not a["detected"]) or "")
    sc = m.get("scyther")
    if sc:
        add("Scyther: all claims verified (Fig. 6)", "all Ok", "%d Ok, %d Fail" % (sc["ok"], sc["fail"]),
            "PASS" if sc["fail"] == 0 else "FAIL",
            "responder-side claims fail: M1/M4/M7/M10 contain nothing only the initiator can produce" if sc["fail"] else "")
    sl = m.get("scale")
    if sl:
        fit = {}
        for s in ("depth, fan-out 3", "depth, 100 nodes"):
            d = [r for r in sl if r["series"] == s]
            fit[s] = linear_r2([r["depth"] for r in d], [r["mean_leaf"] for r in d])
        _, b, r2 = fit["depth, fan-out 3"]
        _, b2, r22 = fit["depth, 100 nodes"]
        add("Delay grows linearly with depth", "linear", "fan-out 3: %.2f s/level, R^2 = %.3f" % (b, r2),
            "PASS" if r2 >= 0.95 and b > 0 else "FAIL",
            "constant fan-out 3, depth 2-5 (4-121 nodes). With a fixed 100 nodes the trend reverses (%.2f s/level, "
            "R^2 = %.3f): shallow trees put many children on one parent's modem" % (b2, r22))
    add("5-D curve overhead 1.3x of 2-D", "1.3x", "not measured", "N.A.", "implementation is 2-D ([18]); no 5-D arithmetic exists")
    return rows


def print_claims(rows):
    section("PAPER CLAIM vs MEASURED")
    print("%-44s %-10s %-50s %-6s" % ("claim", "paper", "measured", "result"))
    for r in rows:
        print("%-44s %-10s %-50s %-6s" % (r["claim"][:44], r["paper"], r["measured"][:50], r["status"]))
        if r["status"] != "PASS" and r["reason"]:
            print("%-44s   reason: %s" % ("", r["reason"]))


def fig_communication(plt, M):
    """Communication cost: the paper's counting model (left) and plaintext vs on-wire bits per message for every
    available mode (right): 1024-bit blocks paper-exact, 528-bit compressed blocks hardened."""
    modes = [k for k in ("paper-exact", "hardened") if k in M]
    ch = M[modes[0]]["chain"]
    data_bits = ch["model_bits"] - ch["auth_only_bits"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 4.8), gridspec_kw={"width_ratios": [1, 1.6]})
    # left: the paper's counting model (plaintext fields), split into handshakes (M1, M2, M4, ...) and data (M3, M6, M9, M12)
    names = ["baselines\n(min-max)", "paper claim\n2112", "this work\n(same model)"]
    hs = [0, 1088, ch["auth_only_bits"]]
    dt = [0, 2112 - 1088, data_bits]
    a1.bar(names[0], 3216, color="#ccc", edgecolor="#888")
    a1.bar(names[0], 3008, color="#999")
    a1.text(0, 3216, "3008-3216", ha="center", va="bottom", fontsize=8)
    a1.bar(names[1:], hs[1:], color="#37a", label="handshakes M1/M2, M4/M5, M7/M8, M10/M11 (8 x 136 bit)")
    a1.bar(names[1], dt[1], bottom=hs[1], color="#9cd", hatch="//", label="data M3/M6/M9/M12, paper: 4 x 256 (derived from 2112)")
    a1.bar(names[2], dt[2], bottom=hs[2], color="#e93", label="data M3/M6/M9/M12, ours: ENV, Alerts, GPS, LOGS as sent")
    for i, (h, d) in enumerate(zip(hs[1:], dt[1:]), 1):
        a1.text(i, h / 2, str(h), ha="center", color="white", fontsize=9, fontweight="bold")
        a1.text(i, h + d / 2, str(d), ha="center", fontsize=9)
        a1.text(i, h + d, str(h + d), ha="center", va="bottom", fontsize=9, fontweight="bold")
    a1.set_ylim(0, 4600)
    a1.set_ylabel("bits per authentication (M1-M12)")
    a1.set_title("Paper's counting model (plaintext fields only, same in both modes)", fontsize=10)
    a1.legend(fontsize=7, loc="upper center")
    # right: per message, plaintext bits vs what PEECC puts on the wire in each mode
    pm = ch["per_message"]
    xs = list(range(len(pm)))
    w = 0.8 / (1 + len(modes))
    a2.bar([x - 0.4 + w / 2 for x in xs], [r["model_bits"] for r in pm], w, color="#37a",
           label="plaintext (paper model): %d bit" % ch["model_bits"])
    for j, mode in enumerate(modes, 1):
        c = M[mode]["chain"]
        a2.bar([x - 0.4 + w / 2 + j * w for x in xs], [r["wire_bits"] for r in c["per_message"]], w, color=MODE_COL[mode],
               label="on the wire, %s: %d bit/block (%s) = %d bit, %.1fx" % (
                   mode, c["block_bits"], "compressed points" if c["compressed"] else "512-bit points", c["wire_bits"],
                   c["wire_bits"] / c["model_bits"]))
    a2.set_xticks(xs); a2.set_xticklabels([r["label"] for r in pm], fontsize=8)
    a2.set_ylabel("bits per message")
    a2.set_ylim(0, max(r["wire_bits"] for mode in modes for r in M[mode]["chain"]["per_message"]) * 1.45)
    title = "Per message: plaintext vs on the wire"
    if len(modes) == 2:
        a, b = (M[k]["chain"]["wire_bits"] for k in modes)
        title += "  (compression: %d -> %d bit, -%.0f %%)" % (a, b, 100 * (1 - b / a))
    a2.set_title(title, fontsize=10)
    a2.legend(fontsize=8, loc="upper left")
    fig.suptitle("Communication cost of one authentication UWS -> BS", fontsize=11, fontweight="bold")
    fig.tight_layout(); fig.savefig(os.path.join(RESULTS, "communication_cost.png"), dpi=120); plt.close(fig)


def charts(m):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    M = load_modes()                                     # the other mode's last run, if any
    M["hardened" if m["hardened"] else "paper-exact"] = m
    fig_communication(plt, M)
    fig_scale(plt, M)


def fig_scale(plt, M):
    """Latency vs depth (fan-out 3 and fixed 100 nodes) and vs node count, for every mode with a scale run."""
    modes = [k for k in ("paper-exact", "hardened") if k in M and M[k].get("scale")]
    if not modes:
        return
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 4.6))
    for mode in modes:
        sc, col = M[mode]["scale"], MODE_COL[mode]
        for s, st in (("depth, fan-out 3", "o-"), ("depth, 100 nodes", "s--")):
            d = sorted([r for r in sc if r["series"] == s], key=lambda r: r["depth"])
            a1.plot([r["depth"] for r in d], [r["mean_leaf"] for r in d], st, color=col,
                    label="%s, %s" % (mode, "fan-out 3 (4-121 nodes)" if "fan" in s else "fixed 100 nodes"))
            if "fan" in s and mode == modes[-1]:
                for r in d:
                    a1.annotate("%d nodes" % r["nodes"], (r["depth"], r["mean_leaf"]), textcoords="offset points",
                                xytext=(-14, -14), fontsize=7)
        n = sorted([r for r in sc if r["series"] == "nodes"], key=lambda r: r["nodes"])
        a2.plot([r["nodes"] for r in n], [r["mean_leaf"] for r in n], "o-", color=col, label="%s, mean leaf -> BS" % mode)
        a2.plot([r["nodes"] for r in n], [r["end_to_end"] for r in n], "s--", color=col, label="%s, all authenticated" % mode)
    a1.set_xticks([2, 3, 4, 5])
    a1.set_xlabel("tree depth (levels)"); a1.set_ylabel("mean UWS -> BS authentication latency (s)")
    a1.set_title("Latency vs depth (fixed 100 nodes: shallow trees crowd the parents)", fontsize=10); a1.legend(fontsize=7)
    a2.set_xlabel("nodes"); a2.set_ylabel("seconds"); a2.set_title("Latency vs nodes (depth 5)", fontsize=10); a2.legend(fontsize=7)
    fig.suptitle("Scalability: authentication latency (paper-exact 1024-bit blocks vs hardened 528-bit compressed blocks)",
                 fontsize=11, fontweight="bold")
    fig.tight_layout(); fig.savefig(os.path.join(RESULTS, "latency.png"), dpi=120); plt.close(fig)


# ============================================================================= figures (claims, improvements, performance)
MODE_COL = {"paper-exact": "#c0392b", "hardened": "#2e8b57"}
OK_COL, BAD_COL, NA_COL, MID_COL = "#2e8b57", "#c0392b", "#999999", "#e69b2e"


def load_modes():
    """Saved metrics of both modes (results/metrics_<mode>.json), as written by --all and --all --hardened."""
    out = {}
    for mode in ("paper-exact", "hardened"):
        path = os.path.join(RESULTS, "metrics_%s.json" % mode)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                out[mode] = json.load(f)
    return out


def fig_claims(plt, M):
    """Scorecard: every quantitative claim as measured / claimed (log scale), plus the qualitative claims."""
    q = []                                                     # (label, claimed, {mode: measured}, unit, lower_is_better)
    any_m = next(iter(M.values()))
    q.append(("Communication, paper model", 2112, {k: v["chain"]["model_bits"] for k, v in M.items()}, "bit"))
    q.append(("Communication, on the wire", 2112, {k: v["chain"]["wire_bits"] for k, v in M.items()}, "bit"))
    q.append(("Transmission time at 10 kbps", 211, {k: v["chain"]["wire_tx_ms"] for k, v in M.items()}, "ms"))
    for e in ("UWS", "SUB", "B", "SAT", "BS"):
        q.append(("Computation %s" % e, PAPER["comp_ms"][e], {k: v["chain"]["entities"][e]["compute_ms"] for k, v in M.items()}, "ms"))
    q.append(("UWS energy", 48.8, {k: v["chain"]["entities"]["UWS"]["energy_uj"] for k, v in M.items()}, "uJ"))
    if "fallback" in any_m:
        q.append(("Mobile re-auth. computation", 1.0, {k: v["fallback"]["mobile_reauth"]["compute_ms"] for k, v in M.items()}, "ms"))
    q.append(("Registry storage of a UWS", 250, {k: max(e["storage_bytes"] for n, e in v["fig1_storage"].items()
                                                     if n.startswith("S") and n[1:].isdigit()) for k, v in M.items()}, "B"))
    fig = plt.figure(figsize=(13, 7.2))
    ax = fig.add_axes([0.25, 0.1, 0.43, 0.8])
    import math
    y = list(range(len(q)))[::-1]
    modes = list(M)
    h = 0.8 / len(modes)
    for j, mode in enumerate(modes):
        ratios = [qq[2][mode] / qq[1] for qq in q]
        ys = [yy + (j - (len(modes) - 1) / 2) * h for yy in y]
        ax.barh(ys, [math.log10(r) for r in ratios], h * 0.9, color=[OK_COL if r <= 1 else BAD_COL for r in ratios],
                alpha=0.95 if mode == "paper-exact" else 0.5, hatch="" if mode == "paper-exact" else "//",
                edgecolor="black", linewidth=0.4)
        for yy, r, qq in zip(ys, ratios, q):
            v = qq[2][mode]
            ax.text(math.log10(r) + (0.05 if r >= 1 else -0.05), yy, "%s %s (%.1fx)" % (("%.0f" if v >= 10 else "%.2f") % v, qq[3], r),
                    va="center", ha="left" if r >= 1 else "right", fontsize=7)
    ax.axvline(0, color="black", linewidth=1.2)
    ax.set_yticks(y); ax.set_yticklabels(["%s\n(paper: %g %s)" % (qq[0], qq[1], qq[3]) for qq in q], fontsize=8)
    ax.set_xlabel("measured / paper claim  (log10;  left of the line = claim met)")
    ax.set_xlim(-1.5, 3.4)
    ax.set_title("Quantitative claims", fontsize=10)
    ax.grid(axis="x", alpha=0.3)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=BAD_COL, label="claim not met"), Patch(color=OK_COL, label="claim met"),
                       Patch(facecolor="white", edgecolor="black", label="upper bar: hardened (hatched)"),
                       Patch(facecolor="#888", edgecolor="black", label="lower bar: paper-exact (solid)")],
              fontsize=7, loc="lower right")
    # qualitative claims
    ax2 = fig.add_axes([0.72, 0.1, 0.26, 0.8]); ax2.axis("off")
    rows = []
    for k, v in M.items():
        for r in v["claims"]:
            if r["claim"].startswith(("Attacks", "Scyther", "Delay grows", "5-D", "30-34")):
                rows.append(("%s%s" % (r["claim"], "" if r["claim"].startswith("Attacks") else ""), r["measured"], r["status"]))
        break
    seen, uniq = set(), []
    for r in rows:
        if r[0] not in seen:
            seen.add(r[0]); uniq.append(r)
    ax2.set_title("Qualitative claims", fontsize=10)
    for i, (c, mval, stt) in enumerate(uniq):
        yy = 0.92 - i * 0.14
        col = OK_COL if stt == "PASS" else NA_COL if stt == "N.A." else BAD_COL
        ax2.add_patch(plt.Rectangle((0, yy - 0.05), 1, 0.11, color=col, alpha=0.18, transform=ax2.transAxes))
        ax2.text(0.02, yy + 0.02, c, fontsize=8.5, fontweight="bold", transform=ax2.transAxes)
        ax2.text(0.02, yy - 0.025, mval[:52], fontsize=7.5, transform=ax2.transAxes)
        ax2.text(0.98, yy, stt, fontsize=9, fontweight="bold", color=col, ha="right", transform=ax2.transAxes)
    fig.suptitle("Paper claims vs measured (IoT Sec. VI and Fig. 6)", fontsize=12, fontweight="bold")
    fig.savefig(os.path.join(RESULTS, "claims_scorecard.png"), dpi=120); plt.close(fig)


def fig_security(plt, M):
    """Improvement in security: attack outcome matrix for both modes, and the K-public eavesdropper on M1-M12."""
    any_m = next(iter(M.values()))
    att = any_m["attacks"]
    names = [a["name"] for a in att["paper-exact"]]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 5.6), gridspec_kw={"width_ratios": [2.2, 1]})
    for j, mode in enumerate(("paper-exact", "hardened")):
        for i, a in enumerate(att[mode]):
            col = OK_COL if a["detected"] else BAD_COL
            a1.add_patch(plt.Rectangle((j, len(names) - 1 - i), 0.96, 0.92, color=col, alpha=0.85))
            a1.text(j + 0.48, len(names) - 1 - i + 0.46, "detected" if a["detected"] else "NOT detected",
                    ha="center", va="center", color="white", fontsize=8, fontweight="bold")
    a1.set_xlim(0, 2); a1.set_ylim(0, len(names))
    a1.set_xticks([0.48, 1.48]); a1.set_xticklabels(["paper-exact [18]", "hardened"], fontsize=9)
    a1.set_yticks([i + 0.46 for i in range(len(names))]); a1.set_yticklabels(names[::-1], fontsize=8)
    a1.tick_params(length=0)
    det = [sum(a["detected"] for a in att[m]) for m in ("paper-exact", "hardened")]
    a1.set_title("Attacks detected: paper-exact %d / %d, hardened %d / %d" % (det[0], len(names), det[1], len(names)), fontsize=10)
    for s in a1.spines.values():
        s.set_visible(False)
    read = {}
    for m in ("paper-exact", "hardened"):
        a = next(x for x in att[m] if x["name"].startswith("K-public"))
        read[m] = int(re.search(r"read (\d+) of (\d+)", a["detail"]).group(1))
    a2.bar(list(read), list(read.values()), color=[MODE_COL[m] for m in read])
    for i, v in enumerate(read.values()):
        a2.text(i, v + 0.2, "%d of 12" % v, ha="center", fontweight="bold")
    a2.set_ylim(0, 13.5); a2.set_ylabel("messages M1-M12 read without any key")
    a2.set_title("Keyless eavesdropper\n(K computed from the public B_x)", fontsize=10)
    fig.text(0.01, 0.01, "Still open in both modes: initiator impersonation (M1 has no proof of the private key) and a delay of "
             "exactly one 8-bit timestamp period (12.8 s).", fontsize=8, color=BAD_COL)
    fig.suptitle("Improvement 1: security (simulate.py --attacks, each attack on a fresh network)", fontsize=12, fontweight="bold")
    fig.tight_layout(rect=(0, 0.03, 1, 0.95)); fig.savefig(os.path.join(RESULTS, "improvement_security.png"), dpi=120); plt.close(fig)


def fig_cost(plt, M, lib):
    """Improvement in cost: multiplier size, point operations, C time, computation, bits on the wire, energy."""
    Bx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    _, Kp = lib.pentatope_K(Bx)
    hk = [lib.pentatope_K(secrets.randbelow(N - 1) + 1)[1] % N for _ in range(200)]
    bits = {"paper-exact": Kp.bit_length(), "hardened": sum(k.bit_length() for k in hk) / len(hk)}
    ops = {"paper-exact": (Kp.bit_length() - 1, bin(Kp).count("1") - 1),
           "hardened": (sum(k.bit_length() - 1 for k in hk) / len(hk), sum(bin(k).count("1") - 1 for k in hk) / len(hk))}
    fig, axs = plt.subplots(2, 3, figsize=(15, 8.4))
    ax = axs.flatten()
    modes = ["paper-exact", "hardened"]
    have = [m for m in modes if m in M]
    cols = [MODE_COL[m] for m in modes]
    w = 0.38

    def label_bars(a, xs, vals, fmt="%.0f", bold=True):
        for x, v in zip(xs, vals):
            a.text(x, v, fmt % v, ha="center", va="bottom", fontsize=8, fontweight="bold" if bold else "normal")

    ax[0].bar(modes, [bits[m] for m in modes], color=cols)
    label_bars(ax[0], range(2), [bits[m] for m in modes])
    ax[0].set_title("Scalar K (bits)", fontsize=10); ax[0].set_ylim(0, bits["paper-exact"] * 1.12)
    dbl = [ops[m][0] for m in modes]; add = [ops[m][1] for m in modes]
    ax[1].bar(modes, dbl, color="#5b8cc0", label="doublings")
    ax[1].bar(modes, add, bottom=dbl, color="#f0b04a", label="additions")
    label_bars(ax[1], range(2), [a + b for a, b in zip(dbl, add)])
    ax[1].set_title("Point operations per K*P", fontsize=10); ax[1].legend(fontsize=8)
    ax[1].set_ylim(0, (dbl[0] + add[0]) * 1.12)
    lab = ["keygen", "encrypt_block", "decrypt_block"]
    for j, m in enumerate(have):
        vals = [M[m]["c_bench_ms"][k] for k in lab]
        xs = [i + (j - 0.5) * w for i in range(3)]
        ax[2].bar(xs, vals, w, color=MODE_COL[m], label=m)
        label_bars(ax[2], xs, vals, "%.1f", False)
    ax[2].set_xticks(range(3)); ax[2].set_xticklabels(["keygen", "encrypt\n(1 block)", "decrypt\n(1 block)"])
    ax[2].set_ylabel("ms (C, peecc_bench)"); ax[2].set_title("Measured C time per operation", fontsize=10); ax[2].legend(fontsize=8)
    ents = ["UWS", "SUB", "B", "SAT", "BS"]
    for j, m in enumerate(have):
        vals = [M[m]["chain"]["entities"][e]["compute_ms"] for e in ents]
        ax[3].bar([i + (j - 0.5) * w for i in range(5)], vals, w, color=MODE_COL[m], label=m)
    ax[3].plot(range(5), [PAPER["comp_ms"][e] for e in ents], "k_", markersize=22, mew=2, label="paper claim (0.4 / 0.5 ms)")
    ax[3].set_yscale("log"); ax[3].set_xticks(range(5)); ax[3].set_xticklabels(ents)
    ax[3].set_ylabel("ms per authentication cycle (log)"); ax[3].set_title("Protocol computation per entity", fontsize=10)
    ax[3].set_ylim(0.2, 3000)
    ax[3].legend(fontsize=7, loc="upper left", ncol=2)
    wire = [M[m]["chain"]["wire_bits"] for m in have]
    ax[4].bar(have, wire, color=[MODE_COL[m] for m in have])
    label_bars(ax[4], range(len(have)), wire)
    ax[4].axhline(2112, color="black", linestyle="--", label="paper claim 2112 bit (plaintext fields only)")
    ax[4].legend(fontsize=8, loc="upper right")
    ax[4].set_xticks(range(len(have)))
    ax[4].set_xticklabels(["%s\n(%d bit / block)" % (m, M[m]["chain"]["block_bits"]) for m in have])
    ax[4].set_ylabel("bits on the wire, M1-M12"); ax[4].set_ylim(0, max(wire) * 1.15)
    ax[4].set_title("Communication: compressed points (33 instead of 64 B)", fontsize=10)
    for j, m in enumerate(have):
        vals = [M[m]["chain"]["entities"][e]["energy_uj"] for e in ents]
        xs = [i + (j - 0.5) * w for i in range(5)]
        ax[5].bar(xs, vals, w, color=MODE_COL[m], label=m)
        label_bars(ax[5], xs, vals, "%.0f", False)
    ax[5].axhline(PAPER["uws_energy_uj"], color="black", linestyle="--", label="paper's UWS total 48.8 uJ")
    ax[5].set_xticks(range(5)); ax[5].set_xticklabels(ents); ax[5].set_ylabel("uJ per authentication cycle")
    ax[5].set_title("Energy (paper's values, ECC scaled by scalar bits)", fontsize=10); ax[5].legend(fontsize=8)
    fig.suptitle("Improvement 2: cost  (hardened: K = (S^2+S+41) mod N, 256 instead of 2029 bit, and compressed points)",
                 fontsize=12, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.95)); fig.savefig(os.path.join(RESULTS, "improvement_cost.png"), dpi=120); plt.close(fig)


def fig_entities(plt, M):
    """Performance per entity: counted operations (identical in both modes) and energy in both modes."""
    m = M.get("paper-exact") or next(iter(M.values()))
    ents = ["UWS", "SUB", "B", "SAT", "BS"]
    E = m["chain"]["entities"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 4.6))
    keys = [("ecc_mul", "ECC scalar mult.", "#5b8cc0"), ("hash", "hash", "#9b59b6"), ("enc", "PEECC encryptions", "#f0b04a"),
            ("dec", "PEECC decryptions", "#5cb85c")]
    w = 0.2
    for j, (k, lab, col) in enumerate(keys):
        a1.bar([i + (j - 1.5) * w for i in range(5)], [E[e][k] for e in ents], w, color=col, label=lab)
    a1.set_xticks(range(5)); a1.set_xticklabels(ents); a1.set_ylabel("count per full cycle")
    a1.set_title("Operations per entity (same count in both modes)", fontsize=10); a1.legend(fontsize=8)
    a1.text(-0.4, max(E[e]["ecc_mul"] for e in ents) * 0.97, "paper's UWS count:\n1 ECC, 2 hash, 2 enc, 2 dec", fontsize=8,
            ha="left", va="top", bbox=dict(fc="white", ec="#aaa"))
    modes = [k for k in ("paper-exact", "hardened") if k in M]
    w2 = 0.38
    for j, mode in enumerate(modes):
        Em = M[mode]["chain"]["entities"]
        xs = [i + (j - 0.5) * w2 for i in range(5)]
        a2.bar(xs, [Em[e]["energy_uj"] for e in ents], w2, color=MODE_COL[mode], label="%s (K %d bit)" % (mode, M[mode]["chain"]["k_bits"]))
        for x, e in zip(xs, ents):
            a2.text(x, Em[e]["energy_uj"], "%.0f" % Em[e]["energy_uj"], ha="center", va="bottom", fontsize=7)
    a2.plot(range(5), [E[e]["energy_flat_uj"] for e in ents], "k_", markersize=26, mew=1.5,
            label="paper's flat model (24 uJ per ECC op)")
    a2.axhline(PAPER["uws_energy_uj"], color="black", linestyle="--", linewidth=1, label="paper's UWS total 48.8 uJ")
    a2.set_yscale("log"); a2.set_ylim(30, 30000); a2.set_xticks(range(5)); a2.set_xticklabels(ents)
    a2.set_ylabel("uJ per authentication cycle (log)")
    a2.set_title("Energy: ECC charged 24 uJ per 256 scalar bits", fontsize=10); a2.legend(fontsize=7, loc="upper left", ncol=2)
    fig.suptitle("Performance: operations and energy per entity for one authentication", fontsize=12, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.93)); fig.savefig(os.path.join(RESULTS, "performance_entities.png"), dpi=120); plt.close(fig)


def fig_latency_breakdown(plt, M):
    """Performance: where the authentication time goes (per hop), and the fallback scenarios."""
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 4.4))
    modes = [m for m in ("paper-exact", "hardened") if m in M]
    hops = list(M[modes[0]]["chain"]["per_hop"])
    for j, m in enumerate(modes):
        ph = M[m]["chain"]["per_hop"]
        tx = [ph[h]["tx_s"] for h in hops]; pr = [ph[h]["prop_s"] for h in hops]
        x = [i + (j - 0.5) * 0.38 for i in range(len(hops))]
        a1.bar(x, tx, 0.36, color="#5b8cc0" if j == 0 else "#a9c6e6", label="transmission at 10 kbps (%s)" % m)
        a1.bar(x, pr, 0.36, bottom=tx, color="#f0b04a" if j == 0 else "#f6d39c", label="propagation 1500 m/s (%s)" % m)
    a1.set_xticks(range(len(hops))); a1.set_xticklabels([h.replace("-", " - ") for h in hops], fontsize=8)
    a1.set_ylabel("seconds per hop (3 messages)")
    tot = ", ".join("%s %.2f s" % (m, M[m]["chain"]["latency_s"]) for m in modes)
    a1.set_title("Per hop: transmission of the PEECC blocks + propagation\nend-to-end incl. computation: %s" % tot, fontsize=9)
    a1.set_ylim(0, 1.6)
    a1.legend(fontsize=7, loc="upper left", ncol=2)
    if all("fallback" in M[m] for m in modes):
        sc = [("buoy_down", "B1 down ->\nfallback B2"), ("sat_delayed", "SAT1 late ->\nfallback SAT2"), ("mobile_reauth", "mobile UWS\nre-auth (M1-M3)")]
        for j, m in enumerate(modes):
            vals = [M[m]["fallback"][k]["seconds"] for k, _ in sc]
            x = [i + (j - 0.5) * 0.38 for i in range(3)]
            a2.bar(x, vals, 0.36, color=MODE_COL[m], label=m)
            for xx, v in zip(x, vals):
                a2.text(xx, v, "%.2f" % v, ha="center", va="bottom", fontsize=8)
        a2.set_xticks(range(3)); a2.set_xticklabels([s[1] for s in sc], fontsize=8)
        a2.set_ylabel("seconds until a session exists"); a2.legend(fontsize=8)
        a2.set_title("Fallback and re-authentication (IoT Sec. IV-D)", fontsize=10)
    fig.suptitle("Performance: authentication latency", fontsize=12, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.93)); fig.savefig(os.path.join(RESULTS, "performance_latency.png"), dpi=120); plt.close(fig)


def fig_scyther(plt, M):
    """Scyther claims (IoT Fig. 6): one row per protocol role, one column per claim type."""
    sc = next((v["scyther"] for v in M.values() if "scyther" in v), None)
    if not sc:
        return
    rows, types = [], ["Secret", "Alive", "Weakagree", "Niagree", "Nisynch"]
    grid = {}
    for c in sc["claims"]:
        role = c["protocol"].replace(",", " : ")
        t = re.match(r"[A-Za-z]+", c["claim"]).group(0)
        if role not in rows:
            rows.append(role)
        grid.setdefault((role, t), []).append(c["result"] == "Ok")
    fig, ax = plt.subplots(figsize=(10, 0.45 * len(rows) + 1.6))
    for i, r in enumerate(rows):
        for j, t in enumerate(types):
            v = grid.get((r, t))
            if v is None:
                col, txt = "#eeeeee", "-"
            else:
                ok = sum(v)
                col = OK_COL if ok == len(v) else BAD_COL if ok == 0 else MID_COL
                txt = "Ok" if ok == len(v) else "Fail" if ok == 0 else "%d/%d Ok" % (ok, len(v))
                if t == "Secret" and len(v) > 1:
                    txt = "%d/%d Ok" % (ok, len(v))
            ax.add_patch(plt.Rectangle((j, len(rows) - 1 - i), 0.95, 0.9, color=col, alpha=0.85))
            ax.text(j + 0.47, len(rows) - 1 - i + 0.45, txt, ha="center", va="center", color="white" if v else "#777",
                    fontsize=8, fontweight="bold")
    ax.set_xlim(0, len(types)); ax.set_ylim(0, len(rows))
    ax.set_xticks([j + 0.47 for j in range(len(types))]); ax.set_xticklabels(types)
    ax.set_yticks([i + 0.45 for i in range(len(rows))]); ax.set_yticklabels(rows[::-1], fontsize=8)
    ax.tick_params(length=0); ax.xaxis.tick_top()
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Scyther (--max-runs=5): %d Ok, %d Fail. Paper Fig. 6: all verified.\n"
                 "Initiators (first role of each hop) keep secrecy and aliveness; responders cannot authenticate the initiator."
                 % (sc["ok"], sc["fail"]), fontsize=9, pad=24)
    fig.tight_layout(); fig.savefig(os.path.join(RESULTS, "scyther_claims.png"), dpi=120); plt.close(fig)


def figures(lib):
    """All figures from results/metrics_<mode>.json (run --all and --all --hardened first for both modes)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    M = load_modes()
    if not M:
        print("no results/metrics_<mode>.json yet: run simulate.py --all (and --all --hardened)")
        return []
    fig_claims(plt, M)
    fig_communication(plt, M)
    fig_scale(plt, M)
    fig_security(plt, M)
    fig_cost(plt, M, lib)
    fig_entities(plt, M)
    fig_latency_breakdown(plt, M)
    fig_scyther(plt, M)
    out = ["communication_cost", "latency", "claims_scorecard", "improvement_security", "improvement_cost", "performance_entities", "performance_latency",
           "scyther_claims"]
    print("Figures (modes: %s): %s" % (", ".join(M), ", ".join("results/%s.png" % o for o in out)))
    return out


def flatten(prefix, v, out):
    if isinstance(v, dict):
        for k, x in v.items():
            flatten("%s.%s" % (prefix, k) if prefix else str(k), x, out)
    elif isinstance(v, list):
        for i, x in enumerate(v):
            flatten("%s[%d]" % (prefix, i), x, out)
    else:
        out.append((prefix, v))


def save(m):
    os.makedirs(RESULTS, exist_ok=True)
    for name in ("metrics.json", "metrics_%s.json" % ("hardened" if m["hardened"] else "paper-exact")):
        with open(os.path.join(RESULTS, name), "w", encoding="utf-8") as f:
            json.dump(m, f, indent=2, default=str)
    rows = []
    flatten("", m, rows)
    with open(os.path.join(RESULTS, "metrics.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])
        w.writerows(rows)


def report(lib, hardened, seed, extra):
    section("METRICS  (mode: %s)" % mode_name(hardened))
    m = dict(mode=mode_name(hardened), hardened=hardened, seed=seed, library=lib.path)
    m["c_bench_ms"] = dict(zip(("keygen", "encrypt_block", "decrypt_block"), lib.bench(50 if hardened else 20, P.mode_of(hardened))))
    m["chain"] = chain_metrics(lib, hardened, seed)
    net = new_network(lib, hardened, seed)
    m["fig1_storage"] = {n: dict(storage_bytes=e.storage_bytes(), peers=len(e.R)) for n, e in net.nodes.items()}
    m.update(extra)
    ch = m["chain"]
    print("Measured C timings (peecc_bench, one block): keygen %.3f ms, encrypt %.3f ms, decrypt %.3f ms"
          % tuple(m["c_bench_ms"].values()))
    print("\nCommunication cost for one authentication UWS -> BS (%d messages):" % ch["messages"])
    print("  %-6s %-10s %12s %12s" % ("msg", "hop", "model bits", "wire bits"))
    for r in ch["per_message"]:
        print("  %-6s %-10s %12d %12d" % (r["label"], "%s->%s" % (r["src"], r["dst"]), r["model_bits"], r["wire_bits"]))
    print("  (a) paper model (plaintext fields, 64/64/8-bit ID/nonce/TS): %d bit, handshakes alone %d bit; "
          "paper claims 2112 bit (derived candidate 4 x (136 + 136 + 256), flagged: the paper gives only the total)"
          % (ch["model_bits"], ch["auth_only_bits"]))
    print("      transmission at 10 kbps: %.0f ms (paper: 211 ms)" % ch["model_tx_ms"])
    print("  (b) actual on-wire size with PEECC blocks (%d bit each, %s): %d bit, %.0f ms at 10 kbps"
          % (ch["block_bits"], "compressed points" if ch["compressed"] else "512-bit points", ch["wire_bits"], ch["wire_tx_ms"]))
    print("  registration message {RID, PU, v}: %d bit each (not part of the 2112-bit figure)" % ch["registration_bits_each"])
    print("\nPer entity (one full cycle: initialization + registration with its neighbours + authentication):")
    print("  %-5s %8s %9s %5s %5s %5s %12s %10s %10s %10s %8s" % ("ent", "ECC mul", "ECC bits", "hash", "enc", "dec", "measured ms",
                                                                  "paper ms", "energy uJ", "flat uJ", "R bytes"))
    for k, e in ch["entities"].items():
        print("  %-5s %8d %9d %5d %5d %5d %12.3f %10.3f %10.1f %10.1f %8d"
              % (k, e["ecc_mul"], e["ecc_bits"], e["hash"], e["enc"], e["dec"], e["compute_ms"], PAPER["comp_ms"][k],
                 e["energy_uj"], e["energy_flat_uj"], e["storage_bytes"]))
    print("  energy model (paper's per-operation values): ECC 24 uJ per 256 scalar bits (K has %d bits here), hash 6 uJ, "
          "enc/dec 3.2 uJ; 'flat' = 24 uJ per ECC operation as in the paper; paper's UWS total 24 + 12 + 12.8 = 48.8 uJ"
          % ch["k_bits"])
    print("\nPropagation delay per hop (distance / 1500 m/s) and transmission time:")
    for h, v in ch["per_hop"].items():
        print("  %-10s propagation %.3f s, transmission %.3f s" % (h, v["prop_s"], v["tx_s"]))
    print("End-to-end authentication latency UWS -> BS: %.3f s;  sessions created: %d" % (ch["latency_s"], ch["sessions"]))
    rows = claims_table(m)
    m["claims"] = rows
    print_claims(rows)
    save(m)
    charts(m)
    print("\nWritten: results/metrics.json, results/metrics.csv, results/communication_cost.png%s"
          % (", results/latency.png" if m.get("scale") else ""))
    return m


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for a in ("demo", "attacks", "fallback", "scale", "all", "hardened", "figures"):
        ap.add_argument("--" + a, action="store_true")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--verbose", action="store_true", help="also print every log line to the console")
    args = ap.parse_args()
    if args.figures and not any((args.demo, args.attacks, args.fallback, args.scale, args.all)):
        figures(P.Peecc())
        return
    if not any((args.demo, args.attacks, args.fallback, args.scale, args.all)):
        args.demo = True
    path = setup_logging()
    console(args.verbose)
    lib = P.Peecc()
    log.info("[INIT] run started, mode: %s, library %s, seed %d", mode_name(args.hardened), lib.path, args.seed)
    print("mode: %s\nlog:  %s" % (mode_name(args.hardened), path))
    extra = {}
    if args.demo or args.all:
        demo(lib, args.hardened, args.seed)
    if args.attacks or args.all:
        extra["attacks"] = {("hardened" if h else "paper-exact"): v for h, v in attacks(lib, args.seed).items()}
    if args.fallback or args.all:
        extra["fallback"] = fallback(lib, args.hardened, args.seed)
    if args.scale or args.all:
        extra["scale"] = scale(lib, args.hardened, args.seed)
    if args.all:
        section("SCYTHER  (local binary, --max-runs=5)")
        sc = scyther()
        if sc is None:
            print("Scyther binary not found at %s" % SCYTHER)
        else:
            extra["scyther"] = sc
            print("%d claims: %d Ok, %d Fail  (%.1f s, full output in results/scyther_output.txt)" % (len(sc["claims"]), sc["ok"],
                                                                                                    sc["fail"], sc["seconds"]))
            for r in sc["claims"]:
                print("  %-16s %-18s %-8s %-5s %s" % (r["protocol"], r["claim"], r["param"], r["result"], r["note"]))
        report(lib, args.hardened, args.seed, extra)
        section("FIGURES")
        figures(lib)
    log.info("[INIT] run finished")


if __name__ == "__main__":
    main()
