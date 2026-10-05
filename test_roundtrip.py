#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import hashlib
import secrets
import sys
from pathlib import Path

import pytest

# Repository root, containing rmau.py
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rmau import (
    crypt_payload,
    decrypt_one,
    encrypt_one,
    get_dek,
    parse,
)

ALIGN = 512
PASSWORD = "RMAU-test-password-€-123"


# ----------------------------------------------------------------------
# Payload tests
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "size",
    [
        0,
        1,
        15,
        16,
        17,
        31,
        32,
        511,
        512,
        513,
        1023,
        1024,
        1025,
        4096,
        100_000,
    ],
)
def test_payload_roundtrip(size):
    original = secrets.token_bytes(size)

    padding = (-len(original)) & 15
    padded = original + b"\0" * padding
    dek = secrets.token_bytes(16)

    encrypted = crypt_payload(
        padded,
        dek,
        ALIGN,
        True,
    )

    decrypted = crypt_payload(
        encrypted,
        dek,
        ALIGN,
        False,
    )

    if padding:
        decrypted = decrypted[:-padding]

    assert decrypted == original


@pytest.mark.parametrize(
    "size",
    [
        16,
        32,
        512,
        1024,
        4096,
    ],
)
def test_ciphertext_differs_from_plaintext(size):
    original = secrets.token_bytes(size)
    dek = secrets.token_bytes(16)

    encrypted = crypt_payload(
        original,
        dek,
        ALIGN,
        True,
    )

    assert encrypted != original
    assert len(encrypted) == len(original)


def test_different_keys_produce_different_ciphertext():
    original = secrets.token_bytes(1024)

    encrypted1 = crypt_payload(
        original,
        secrets.token_bytes(16),
        ALIGN,
        True,
    )

    encrypted2 = crypt_payload(
        original,
        secrets.token_bytes(16),
        ALIGN,
        True,
    )

    assert encrypted1 != encrypted2


def test_encryption_is_deterministic_with_same_dek():
    original = secrets.token_bytes(2048)
    dek = secrets.token_bytes(16)

    encrypted1 = crypt_payload(
        original,
        dek,
        ALIGN,
        True,
    )

    encrypted2 = crypt_payload(
        original,
        dek,
        ALIGN,
        True,
    )

    assert encrypted1 == encrypted2


def test_chunk_boundary_changes_iv():
    original = b"\0" * (ALIGN * 2)
    dek = secrets.token_bytes(16)

    encrypted = crypt_payload(
        original,
        dek,
        ALIGN,
        True,
    )

    first = encrypted[:ALIGN]
    second = encrypted[ALIGN:ALIGN * 2]

    assert first != second


def test_hash_roundtrip():
    original = secrets.token_bytes(8193)

    padding = (-len(original)) & 15
    padded = original + b"\0" * padding
    dek = secrets.token_bytes(16)

    encrypted = crypt_payload(
        padded,
        dek,
        ALIGN,
        True,
    )

    decrypted = crypt_payload(
        encrypted,
        dek,
        ALIGN,
        False,
    )

    if padding:
        decrypted = decrypted[:-padding]

    assert decrypted == original
    assert (
        hashlib.sha256(decrypted).digest()
        == hashlib.sha256(original).digest()
    )


# ----------------------------------------------------------------------
# Complete container tests
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "size",
    [
        0,
        1,
        15,
        16,
        17,
        31,
        32,
        511,
        512,
        513,
        1023,
        1024,
        1025,
        4096,
        100_000,
    ],
)
def test_container_roundtrip(tmp_path, size):
    """
    Complete end-to-end test:

        plaintext
            -> encrypt_one()
            -> .XML container
            -> parse()
            -> get_dek()
            -> decrypt_one()
            -> plaintext

    The final file must be identical byte-for-byte.
    """

    original = secrets.token_bytes(size)

    src = tmp_path / "sample.bin"
    src.write_bytes(original)

    original_hash = hashlib.sha256(original).digest()

    # Encrypt complete container.
    encrypted = encrypt_one(
        src,
        PASSWORD,
    )

    assert encrypted.exists()
    assert encrypted.name == "sample.bin.XML"

    # Inspect the generated container.
    info = parse(encrypted)

    assert info["filename"] == "sample.bin"
    assert info["alignment"] == ALIGN
    assert info["padding"] == ((-size) & 15)

    assert info["start"] % ALIGN == 0
    assert info["start"] >= info["header"]

    # Verify password -> KEK -> wrapped DEK -> DEK.
    dek = get_dek(
        info,
        PASSWORD,
    )

    assert len(dek) == 16

    assert (
        hashlib.sha256(dek).digest()
        == info["hash"]
    )

    # Remove original plaintext so decrypt_one() has to recreate it.
    src.unlink()

    assert not src.exists()

    recovered = decrypt_one(
        encrypted,
        PASSWORD,
    )

    assert recovered == src
    assert recovered.exists()

    result = recovered.read_bytes()

    assert len(result) == size
    assert result == original

    assert (
        hashlib.sha256(result).digest()
        == original_hash
    )


def test_wrong_password(tmp_path):
    src = tmp_path / "secret.bin"
    src.write_bytes(secrets.token_bytes(4096))

    encrypted = encrypt_one(
        src,
        PASSWORD,
    )

    src.unlink()

    with pytest.raises(
        ValueError,
        match="password errata",
    ):
        decrypt_one(
            encrypted,
            "wrong-password",
        )

    # Wrong password must not create plaintext.
    assert not src.exists()

    # Encrypted source must remain untouched.
    assert encrypted.exists()


def test_container_is_not_deterministic(tmp_path):
    """
    encrypt_one() generates a new random DEK and header IV,
    therefore two encryptions of the same plaintext/password
    should produce different containers.
    """

    data = secrets.token_bytes(4096)

    a = tmp_path / "a" / "sample.bin"
    b = tmp_path / "b" / "sample.bin"

    a.parent.mkdir()
    b.parent.mkdir()

    a.write_bytes(data)
    b.write_bytes(data)

    enc_a = encrypt_one(a, PASSWORD)
    enc_b = encrypt_one(b, PASSWORD)

    assert enc_a.read_bytes() != enc_b.read_bytes()


def test_force_protection(tmp_path):
    src = tmp_path / "sample.bin"
    src.write_bytes(b"original")

    encrypted = encrypt_one(
        src,
        PASSWORD,
    )

    # Destination .XML already exists.
    with pytest.raises(FileExistsError):
        encrypt_one(
            src,
            PASSWORD,
        )

    # --force equivalent must succeed.
    encrypt_one(
        src,
        PASSWORD,
        force=True,
    )

    assert encrypted.exists()


def test_delete_after_successful_decryption(tmp_path):
    original = secrets.token_bytes(1025)

    src = tmp_path / "sample.bin"
    src.write_bytes(original)

    encrypted = encrypt_one(
        src,
        PASSWORD,
    )

    src.unlink()

    recovered = decrypt_one(
        encrypted,
        PASSWORD,
        delete=True,
    )

    assert recovered.exists()
    assert recovered.read_bytes() == original

    # Encrypted container must be removed only after success.
    assert not encrypted.exists()
