"""The 4-hop, 12-message NSL-style authentication exchange.

    M1/M2/M3    = UWS  <-> SUB
    M4/M5/M6    = SUB  <-> BUOY
    M7/M8/M9    = BUOY <-> SAT
    M10/M11/M12 = SAT  <-> BS

Within each hop:
    a) initiator -> responder: {tag_a, initiator_ID, fresh_nonce}pk(responder)
    b) responder -> initiator: {tag_b, nonce_i, fresh_nonce_r, responder_ID}pk(initiator)
    c) initiator -> responder: {tag_c, nonce_r}pk(responder)
"""

from __future__ import annotations

import time
from typing import Dict, Tuple

from ..config import TAGS
from ..crypto.peecc import PEECCBackend
from ..models.entity import Entity
from ..simulation.channel import Channel
from .messages import check_timestamp, decrypt_fields, encrypt_fields, new_nonce
from .session import new_session


def _send_message(channel: Channel, crypto: PEECCBackend, entities: Dict[str, Entity],
                   message_name: str, msg_no: int, sender: str, receiver: str,
                   fields, retries_enabled: bool = True):
    """Encrypt ``fields``, attempt delivery through the channel, and decrypt
    on arrival. Returns the decoded field list, or ``None`` on failed
    delivery (loss after exhausting retries)."""
    ciphertext = encrypt_fields(crypto, entities, sender, receiver, fields)
    delivered = channel.transmit(message_name, msg_no, sender, receiver,
                                  ciphertext, fields, retries_enabled=retries_enabled)
    if not delivered:
        return None
    return decrypt_fields(crypto, entities, sender, receiver, ciphertext)


def authenticate_hop(channel: Channel, crypto: PEECCBackend, entities: Dict[str, Entity],
                      sessions: Dict[Tuple[str, str], str],
                      hop: int, initiator: str, responder: str,
                      labels: Tuple[str, str, str],
                      message_numbers: Tuple[int, int, int],
                      message_names: Tuple[str, str, str],
                      verbose: bool = True) -> bool:
    """Run one independent 3-message NSL-style exchange for a single hop."""
    taga, tagb, tagc = labels
    m1, m2, m3 = message_numbers
    n1 = new_nonce()
    sent_ts = time.time()

    decoded1 = _send_message(channel, crypto, entities, message_names[0], m1,
                              initiator, responder, [taga, initiator, str(n1)])
    if decoded1 is None or decoded1 != [taga, initiator, str(n1)]:
        return False

    nr = new_nonce()
    responder_ts = time.time()
    decoded2 = _send_message(channel, crypto, entities, message_names[1], m2,
                              responder, initiator, [tagb, str(n1), str(nr), responder])
    if decoded2 is None or decoded2 != [tagb, str(n1), str(nr), responder]:
        return False

    if not check_timestamp(sent_ts, responder_ts):
        return False

    decoded3 = _send_message(channel, crypto, entities, message_names[2], m3,
                              initiator, responder, [tagc, str(nr)])
    if decoded3 is None or decoded3 != [tagc, str(nr)]:
        return False

    new_session(sessions, initiator, responder)
    channel.energy.use(initiator, "auth")
    channel.energy.use(responder, "auth")
    if verbose:
        print(f"[AUTH OK] {initiator} <-> {responder}  "
              f"Ni={str(n1)[:10]}... Nr={str(nr)[:10]}...")
    return True


def run_ns_authentication(channel: Channel, crypto: PEECCBackend, entities: Dict[str, Entity],
                           sessions: Dict[Tuple[str, str], str],
                           buoy: str = "B1", satellite: str = "SAT1",
                           verbose: bool = True) -> bool:
    """Run the full M1-M12 authentication sequence along one selected path."""
    if verbose:
        print("\n=== M1-M12 NSL AUTHENTICATION ===")
        print(f"Path: U1 -> S1 -> {buoy} -> {satellite} -> BS")

    hops = [
        (1, "U1", "S1", TAGS[1], (1, 2, 3), ("M1", "M2", "M3")),
        (2, "S1", buoy, TAGS[2], (4, 5, 6), ("M4", "M5", "M6")),
        (3, buoy, satellite, TAGS[3], (7, 8, 9), ("M7", "M8", "M9")),
        (4, satellite, "BS", TAGS[4], (10, 11, 12), ("M10", "M11", "M12")),
    ]

    for hop, a, b, tags, nums, names in hops:
        ok = authenticate_hop(channel, crypto, entities, sessions, hop, a, b,
                               tags, nums, names, verbose=verbose)
        if verbose:
            print(f"Hop {hop}: {a} <-> {b}: {'SUCCESS' if ok else 'FAILED'}")
        if not ok:
            return False

    if verbose:
        print("=== ALL M1-M12 MESSAGES SUCCESSFUL ===")
    return True
