from uwcn.crypto.peecc import PEECCBackend
from uwcn.protocol.initialization import initialize_entities
from uwcn.protocol.registration import register_network


def test_register_network_produces_rid_for_every_entity():
    crypto = PEECCBackend()
    entities = initialize_entities(crypto, verbose=False)

    registration_set = register_network(entities, verbose=False)

    assert len(registration_set) == len(entities)
    for entity in entities.values():
        assert "RID" in entity.registered
        assert "THETA" in entity.registered
