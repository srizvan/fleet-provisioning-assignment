from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import escrow

KEYS = Path(__file__).parent.parent / "keys"


@pytest.fixture(scope="module")
def keys():
    return (
        escrow.load_public_key(KEYS / "TEST_ONLY_escrow_public.pem"),
        escrow.load_private_key(KEYS / "TEST_ONLY_escrow_private.pem"),
    )


def test_round_trip(keys):
    pub, priv = keys
    blob = escrow.encrypt(pub, "maple river otter tango zinc", "kit:7:rev:1", "kit_secret")
    assert escrow.decrypt(priv, blob, "kit:7:rev:1", "kit_secret") == "maple river otter tango zinc"


def test_ciphertext_is_randomised(keys):
    pub, _ = keys
    a = escrow.encrypt(pub, "same", "device:100", "device_password")
    b = escrow.encrypt(pub, "same", "device:100", "device_password")
    assert a != b


def test_plaintext_not_in_blob(keys):
    pub, _ = keys
    assert b"maple" not in escrow.encrypt(pub, "maple", "kit:1:rev:1", "kit_secret")


def test_tampered_ciphertext_rejected(keys):
    pub, priv = keys
    blob = bytearray(escrow.encrypt(pub, "secret", "device:100", "device_password"))
    blob[-1] ^= 1
    with pytest.raises(Exception):
        escrow.decrypt(priv, bytes(blob), "device:100", "device_password")


def test_wrong_column_rejected(keys):
    pub, priv = keys
    blob = escrow.encrypt(pub, "secret", "device:100", "device_password")
    with pytest.raises(Exception):
        escrow.decrypt(priv, blob, "device:100", "kit_secret")


def test_other_key_rejected(keys):
    pub, _ = keys
    other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    blob = escrow.encrypt(pub, "secret", "device:100", "device_password")
    with pytest.raises(ValueError):
        escrow.decrypt(other, blob, "device:100", "device_password")
