"""Encryption tests: round-trip, wrong key, corrupted mapping, key separation."""

import pytest

from privacyshield.crypto import (
    encrypt_mapping,
    decrypt_mapping,
    generate_key,
    InvalidKeyError,
    CorruptedMappingError,
)


RECORDS = [
    {"token": "EMAIL_001", "entity_type": "EMAIL", "original": "ada@x.edu"},
    {"token": "PERSON_001", "entity_type": "PERSON", "original": "Ada Lovelace"},
]


def test_encrypt_decrypt_round_trip():
    key = generate_key()
    blob = encrypt_mapping(RECORDS, key)
    out = decrypt_mapping(blob, key)
    assert out == RECORDS


def test_key_not_present_in_blob():
    key = generate_key()
    blob = encrypt_mapping(RECORDS, key)
    assert key.encode() not in blob
    # And no original value appears in plaintext inside the blob.
    assert b"ada@x.edu" not in blob
    assert b"Ada Lovelace" not in blob


def test_wrong_key_raises_invalid_key():
    key = generate_key()
    other = generate_key()
    blob = encrypt_mapping(RECORDS, key)
    with pytest.raises(InvalidKeyError):
        decrypt_mapping(blob, other)


def test_malformed_key_raises_invalid_key():
    key = generate_key()
    blob = encrypt_mapping(RECORDS, key)
    with pytest.raises(InvalidKeyError):
        decrypt_mapping(blob, "not-a-real-key")


def test_corrupted_header_raises_corrupted():
    key = generate_key()
    blob = encrypt_mapping(RECORDS, key)
    tampered = b"XXXX" + blob[4:]
    with pytest.raises(CorruptedMappingError):
        decrypt_mapping(tampered, key)


def test_tampered_ciphertext_is_rejected():
    key = generate_key()
    blob = bytearray(encrypt_mapping(RECORDS, key))
    # Flip a byte deep in the ciphertext body.
    blob[-1] ^= 0xFF
    with pytest.raises((InvalidKeyError, CorruptedMappingError)):
        decrypt_mapping(bytes(blob), key)


def test_two_keys_are_distinct():
    assert generate_key() != generate_key()
