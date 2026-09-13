from uwcn.crypto.peecc import PEECCBackend
from uwcn.protocol.authentication import run_ns_authentication
from uwcn.protocol.initialization import initialize_entities
from uwcn.protocol.registration import register_network
from uwcn.simulation.channel import Channel


def test_full_ns_authentication_can_succeed():
    crypto = PEECCBackend()
    entities = initialize_entities(crypto, verbose=False)
    register_network(entities, verbose=False)
    channel = Channel()
    sessions = {}

    # Loss is probabilistic; run a few attempts and require at least one
    # clean success across the M1-M12 sequence.
    results = [
        run_ns_authentication(channel, crypto, entities, sessions,
                               "B1", "SAT1", verbose=False)
        for _ in range(10)
    ]
    assert any(results)


def test_authentication_establishes_sessions_on_success():
    crypto = PEECCBackend()
    entities = initialize_entities(crypto, verbose=False)
    register_network(entities, verbose=False)
    channel = Channel()
    sessions = {}

    for _ in range(15):
        ok = run_ns_authentication(channel, crypto, entities, sessions,
                                    "B1", "SAT1", verbose=False)
        if ok:
            assert ("U1", "S1") in sessions
            assert ("S1", "B1") in sessions
            break
    else:
        raise AssertionError("authentication never succeeded in 15 attempts")
