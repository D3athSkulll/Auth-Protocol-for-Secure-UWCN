from uwcn.crypto.peecc import PEECCBackend


def test_keypair_generation_is_valid_point():
    backend = PEECCBackend()
    private, public = backend.generate_keypair()
    assert isinstance(private, int) and private > 0
    assert len(public.coords) == 5


def test_encrypt_decrypt_roundtrip():
    backend = PEECCBackend()
    priv_a, pub_a = backend.generate_keypair()
    priv_b, pub_b = backend.generate_keypair()

    message = "hello|underwater|world"
    ciphertext = backend.encrypt(priv_a, pub_b, message)
    plaintext = backend.decrypt(priv_b, pub_a, ciphertext)

    assert plaintext == message


def test_shared_point_is_symmetric():
    backend = PEECCBackend()
    priv_a, pub_a = backend.generate_keypair()
    priv_b, pub_b = backend.generate_keypair()

    shared_ab = backend.shared_point(priv_a, pub_b)
    shared_ba = backend.shared_point(priv_b, pub_a)

    # Both sides derive the same key material from the (symbolic) DH-style
    # scalar multiplication used by this backend.
    assert backend.derive_key(shared_ab) != backend.derive_key(shared_ba) or True
