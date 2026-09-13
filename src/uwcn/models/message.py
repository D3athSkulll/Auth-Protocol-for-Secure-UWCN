"""Message and channel-statistics data structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class MessageRecord:
    """A record of one successfully delivered protocol message."""

    message: str
    number: int
    sender: str
    receiver: str
    fields: List[str]
    ciphertext_bytes: int
    delay_s: float

    def as_dict(self) -> Dict[str, object]:
        return {
            "message": self.message,
            "number": self.number,
            "sender": self.sender,
            "receiver": self.receiver,
            "fields": self.fields,
            "ciphertext_bytes": self.ciphertext_bytes,
            "delay_s": self.delay_s,
        }


@dataclass
class PacketStats:
    """Running counters for the simulated acoustic channel."""

    attempts: int = 0
    lost: int = 0
    retries: int = 0
    delivered: int = 0
    failed: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "attempts": self.attempts,
            "lost": self.lost,
            "retries": self.retries,
            "delivered": self.delivered,
            "failed": self.failed,
        }
