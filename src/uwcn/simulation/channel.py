"""The simulated acoustic channel: combines delay, mobility, loss/retry, and
energy accounting for a single message transmission attempt."""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..config import MAX_RETRY
from ..models.message import MessageRecord, PacketStats
from .delay import acoustic_delay
from .energy import EnergyModel
from .mobility import MobilityModel
from .packet_loss import decide_loss


class Channel:
    """Owns the packet-loss/retry state, delay log, and energy model shared
    by every message sent across the simulated underwater network."""

    def __init__(self, energy: Optional[EnergyModel] = None,
                 mobility: Optional[MobilityModel] = None) -> None:
        self.energy = energy or EnergyModel()
        self.mobility = mobility or MobilityModel()
        self.stats = PacketStats()
        self.delay_log: List[float] = []
        self.hop_delay_log: List[Tuple[int, str, str, float]] = []
        self.message_records: List[MessageRecord] = []

    def transmit(self, message_name: str, msg_no: int, sender: str, receiver: str,
                 ciphertext: bytes, fields: List[str],
                 retries_enabled: bool = True,
                 max_retry: int = MAX_RETRY) -> bool:
        """Attempt to deliver one already-encrypted message. Returns True on
        successful delivery (after logging delay/energy/stats), False if the
        message was ultimately lost after exhausting retries."""
        attempts = 0
        limit = max_retry if retries_enabled else 1
        while attempts < limit:
            attempts += 1
            self.stats.attempts += 1
            delay = acoustic_delay(sender, receiver, self.mobility.offset(sender))
            self.delay_log.append(delay)
            self.hop_delay_log.append((msg_no, sender, receiver, delay))

            if decide_loss():
                self.stats.lost += 1
                if attempts < limit:
                    self.stats.retries += 1
                    continue
                self.stats.failed += 1
                return False

            self.energy.use(sender, "tx")
            self.energy.use(receiver, "rx")
            self.stats.delivered += 1
            self.message_records.append(MessageRecord(
                message=message_name, number=msg_no, sender=sender,
                receiver=receiver, fields=fields,
                ciphertext_bytes=len(ciphertext), delay_s=delay,
            ))
            return True
        return False
