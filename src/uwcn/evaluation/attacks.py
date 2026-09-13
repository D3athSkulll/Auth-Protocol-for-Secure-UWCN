"""Replay / freshness attack evaluation."""

from __future__ import annotations

import time

from ..config import TSW
from ..protocol.messages import check_timestamp


def replay_test(verbose: bool = True) -> bool:
    """Attempt to replay a stale timestamp and confirm it is rejected by the
    freshness window check. Returns True if the (bad) replay was accepted."""
    if verbose:
        print("\n=== REPLAY / FRESHNESS TEST ===")
    old_ts = time.time() - (TSW + 1.0)
    accepted = check_timestamp(old_ts, time.time())
    if verbose:
        print("Replay ACCEPTED (BUG)" if accepted else "Replay blocked")
    return accepted
