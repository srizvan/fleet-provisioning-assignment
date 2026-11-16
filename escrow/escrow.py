"""Helpers for encrypting secrets to the escrow key.

Hybrid construction: a random AES-256-GCM key per secret, wrapped with the
escrow RSA public key. The private key never leaves its offline machine, so
only `encrypt` runs on stations and servers.

Blob layout: key_id (4) | wrapped key (RSA modulus size) | nonce (12) | ciphertext+tag
The associated data binds a ciphertext to the record and column it belongs to.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DOMAIN = b"fleet-escrow-v1"


def key_id(public_key: rsa.RSAPublicKey) -> bytes:
    """First 4 bytes of SHA-256 over the DER SubjectPublicKeyInfo."""
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).digest()[:4]


def _aad(row_key: str, column: str) -> bytes:
    return b"|".join([DOMAIN, column.encode()])


def encrypt(public_key: rsa.RSAPublicKey, plaintext: str, row_key: str, column: str) -> bytes:
    """Encrypt `plaintext` for the record `row_key` (e.g. "kit:42:rev:1") and `column`."""
    k = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    wrapped = public_key.encrypt(k, padding.PKCS1v15())
    ct = AESGCM(k).encrypt(nonce, plaintext.encode(), _aad(row_key, column))
    return key_id(public_key) + wrapped + nonce + ct


def decrypt(private_key: rsa.RSAPrivateKey, blob: bytes, row_key: str, column: str) -> str:
    """Inverse of `encrypt`. Runs only on the offline machine that holds the private key."""
    kid_len, wrapped_len = 4, private_key.key_size // 8
    kid = blob[:kid_len]
    if kid != key_id(private_key.public_key()):
        raise ValueError("blob was encrypted to a different escrow key")
    wrapped = blob[kid_len : kid_len + wrapped_len]
    nonce = blob[kid_len + wrapped_len : kid_len + wrapped_len + 12]
    ct = blob[kid_len + wrapped_len + 12 :]
    k = private_key.decrypt(wrapped, padding.PKCS1v15())
    return AESGCM(k).decrypt(nonce, ct, _aad(row_key, column)).decode()


def load_public_key(path: str) -> rsa.RSAPublicKey:
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
