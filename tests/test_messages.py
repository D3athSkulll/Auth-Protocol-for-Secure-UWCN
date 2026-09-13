import time

from uwcn.crypto.peecc import PEECCBackend
from uwcn.protocol.initialization import initialize_entities
from uwcn.protocol.messages import (
    check_timestamp,
    decrypt_fields,
    encrypt_fields,
    new_nonce,
)


def test_new_nonce_is_random_and_positive():
    n1 = new_nonce()
    n2 = new_nonce()
    assert n1 >= 0 and n2 >= 0
    assert n1 != n2  # extremely unlikely to collide


def test_check_timestamp_within_window():
    now = time.time()
    assert check_timestamp(now, now + 1.0) is True
    assert check_timestamp(now, now + 10.0) is False


def test_encrypt_decrypt_fields_roundtrip():
    crypto = PEECCBackend()
    entities = initialize_entities(crypto, verbose=False)

    fields = ["tag", "U1", "12345"]
    ciphertext = encrypt_fields(crypto, entities, "U1", "S1", fields)
    decoded = decrypt_fields(crypto, entities, "U1", "S1", ciphertext)

    assert decoded == fields
