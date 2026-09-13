from uwcn.models.entity import Entity
from uwcn.models.point import PEECCPoint
from uwcn.simulation.channel import Channel
from uwcn.simulation.energy import EnergyModel


def test_channel_transmit_updates_stats_on_delivery(monkeypatch):
    channel = Channel()

    # Force delivery (no loss) to deterministically test the success path.
    monkeypatch.setattr("uwcn.simulation.channel.decide_loss", lambda: False)

    delivered = channel.transmit("M1", 1, "U1", "S1", b"ciphertext", ["a", "b"])

    assert delivered is True
    assert channel.stats.attempts == 1
    assert channel.stats.delivered == 1
    assert len(channel.message_records) == 1


def test_channel_transmit_fails_after_max_retries(monkeypatch):
    channel = Channel()
    monkeypatch.setattr("uwcn.simulation.channel.decide_loss", lambda: True)

    delivered = channel.transmit("M1", 1, "U1", "S1", b"ciphertext", ["a", "b"],
                                  max_retry=3)

    assert delivered is False
    assert channel.stats.failed == 1
    assert channel.stats.attempts == 3


def test_energy_model_tracks_usage():
    energy = EnergyModel(initial_uJ=1000.0)
    energy.use("U1", "tx")
    assert energy.battery["U1"] < 1000.0
