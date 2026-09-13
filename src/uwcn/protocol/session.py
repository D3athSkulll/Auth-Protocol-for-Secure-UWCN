"""Session-key bookkeeping and the (protocol-independent) sensor data flow.

Data flow is kept separate from the Scyther M1-M12 authentication messages.
This avoids treating M3/M6/M9/M12 simultaneously as NSL messages and as
sensor/data packets.
"""

from __future__ import annotations

import random
from typing import Dict, Tuple

from ..crypto.hash import h
from .messages import new_nonce


def new_session(sessions: Dict[Tuple[str, str], str], a: str, b: str) -> str:
    sid = h("SESSION", a, b, new_nonce())
    sessions[(a, b)] = sid
    sessions[(b, a)] = sid
    return sid


def run_data_flow(buoy: str = "B1", satellite: str = "SAT1",
                   verbose: bool = True) -> Dict[str, object]:
    """Simulate the logical sensor/environment/GPS/log data package flowing
    UWS -> SUB -> BUOY -> SAT -> BS, independent of the NSL authentication."""
    if verbose:
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

    if verbose:
        print(f"UWS sensor data: {sensor}")
        print(f"SUB receives ENV and forwards it to {buoy}")
        print(f"BUOY adds GPS={gps} and forwards to {satellite}")
        print("SAT adds LOGS and forwards the complete package to BS")

    return {"ENV": sensor, "ALERTS": alerts, "GPS": gps, "LOGS": logs}
