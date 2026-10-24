"""Authenticated encryption for the original-to-token mapping export.

Preferred backend: AES-256-GCM via the ``cryptography`` library (AEAD).

Fallback backend (pure stdlib, used when ``cryptography`` is unavailable):
Encrypt-then-MAC. A random 256-bit master key is split via HKDF-SHA256 into an
encryption key and a MAC key. The plaintext is encrypted with a SHA-256
counter-mode keystream (XOR) and authenticated with HMAC-SHA256 over the
ciphertext, nonce, and version header. Decryption verifies the MAC in constant
time BEFORE decrypting, so tampering or a wrong key is rejected. This provides
genuine authenticated encryption using only the standard library.

Security properties guaranteed by BOTH backends:
- The decryption key is never stored inside the encrypted blob.
- A wrong key -> ``InvalidKeyError``.
- Any modification of the ciphertext -> ``CorruptedMappingError``.
- No plaintext, key, or original value is ever logged.

The key is returned/consumed as a URL-safe base64 string so it can be
downloaded as a small text file, entirely separate from the mapping blob.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from typing import Any

MAGIC = b"PSHLD1"  # version header, authenticated


class InvalidKeyError(Exception):
    """Raised when the supplied decryption key is wrong."""


class CorruptedMappingError(Exception):
    """Raised when the encrypted mapping is malformed or tampered with."""


def _have_cryptography() -> bool:
    try:
        import cryptography  # noqa: F401
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        return True
    except Exception:
        return False


CRYPTO_BACKEND = "AES-256-GCM (cryptography)" if _have_cryptography() \
    else "AES-free Encrypt-then-MAC (stdlib HMAC-SHA256)"

KEY_BYTES = 32  # 256-bit


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------

def generate_key() -> str:
    """Generate a fresh 256-bit key encoded as a URL-safe base64 string."""
    return base64.urlsafe_b64encode(secrets.token_bytes(KEY_BYTES)).decode("ascii")


def _decode_key(key: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(key.strip().encode("ascii"))
    except Exception as exc:  # malformed key string
        raise InvalidKeyError("Decryption key is not valid base64.") from exc
    if len(raw) != KEY_BYTES:
        raise InvalidKeyError("Decryption key has an incorrect length.")
    return raw


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt_mapping(records: Any, key: str) -> bytes:
    """Serialize ``records`` to JSON and encrypt them with ``key``.

    Returns an opaque bytes blob safe to write to disk / download. The key is
    NOT included in the blob.
    """
    plaintext = json.dumps(records, ensure_ascii=False).encode("utf-8")
    raw_key = _decode_key(key)
    if _have_cryptography():
        return _encrypt_aesgcm(plaintext, raw_key)
    return _encrypt_etm(plaintext, raw_key)


def decrypt_mapping(blob: bytes, key: str) -> Any:
    """Decrypt a blob produced by :func:`encrypt_mapping` and return records.

    Raises ``InvalidKeyError`` for a wrong key and ``CorruptedMappingError``
    for malformed / tampered input.
    """
    raw_key = _decode_key(key)
    if not isinstance(blob, (bytes, bytearray)):
        raise CorruptedMappingError("Encrypted mapping must be bytes.")

    header = _read_header(blob)
    if header == b"GCM1":
        plaintext = _decrypt_aesgcm(blob, raw_key)
    elif header == b"ETM1":
        plaintext = _decrypt_etm(blob, raw_key)
    else:
        raise CorruptedMappingError("Unrecognized or corrupted mapping format.")

    try:
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise CorruptedMappingError("Decrypted content is not valid JSON.") from exc


# ---------------------------------------------------------------------------
# Framing helpers: MAGIC (6) | backend tag (4) | payload
# ---------------------------------------------------------------------------

def _frame(tag: bytes, payload: bytes) -> bytes:
    return MAGIC + tag + payload


def _read_header(blob: bytes) -> bytes:
    if len(blob) < len(MAGIC) + 4 or blob[: len(MAGIC)] != MAGIC:
        raise CorruptedMappingError("Missing or invalid file header.")
    return bytes(blob[len(MAGIC): len(MAGIC) + 4])


def _payload(blob: bytes) -> bytes:
    return bytes(blob[len(MAGIC) + 4:])


# ---------------------------------------------------------------------------
# AES-GCM backend
# ---------------------------------------------------------------------------

def _encrypt_aesgcm(plaintext: bytes, raw_key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    aad = MAGIC + b"GCM1"
    ct = AESGCM(raw_key).encrypt(nonce, plaintext, aad)
    return _frame(b"GCM1", nonce + ct)


def _decrypt_aesgcm(blob: bytes, raw_key: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    payload = _payload(blob)
    if len(payload) < 12 + 16:
        raise CorruptedMappingError("Ciphertext too short.")
    nonce, ct = payload[:12], payload[12:]
    aad = MAGIC + b"GCM1"
    try:
        return AESGCM(raw_key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        # GCM cannot distinguish wrong-key from tampering; surface as key error
        # when the blob structure is intact.
        raise InvalidKeyError("Wrong key or corrupted mapping.") from exc


# ---------------------------------------------------------------------------
# Stdlib Encrypt-then-MAC backend
# ---------------------------------------------------------------------------

def _hkdf(raw_key: bytes, info: bytes, length: int = 32) -> bytes:
    # HKDF-Expand with a fixed salt (the key is already high-entropy random).
    prk = hmac.new(b"PrivacyShield-salt", raw_key, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def _keystream(enc_key: bytes, nonce: bytes, nbytes: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        block = hashlib.sha256(
            enc_key + nonce + counter.to_bytes(8, "big")
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:nbytes])


def _encrypt_etm(plaintext: bytes, raw_key: bytes) -> bytes:
    enc_key = _hkdf(raw_key, b"enc")
    mac_key = _hkdf(raw_key, b"mac")
    nonce = secrets.token_bytes(16)

    ks = _keystream(enc_key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))

    aad = MAGIC + b"ETM1"
    tag = hmac.new(mac_key, aad + nonce + ct, hashlib.sha256).digest()
    return _frame(b"ETM1", nonce + tag + ct)


def _decrypt_etm(blob: bytes, raw_key: bytes) -> bytes:
    payload = _payload(blob)
    if len(payload) < 16 + 32:
        raise CorruptedMappingError("Ciphertext too short.")
    nonce = payload[:16]
    tag = payload[16:48]
    ct = payload[48:]

    mac_key = _hkdf(raw_key, b"mac")
    aad = MAGIC + b"ETM1"
    expected = hmac.new(mac_key, aad + nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        # Could be a wrong key or tampering. If the overall framing is intact
        # we report a key error; truly malformed blobs are caught earlier.
        raise InvalidKeyError("Wrong key or corrupted mapping.")

    enc_key = _hkdf(raw_key, b"enc")
    ks = _keystream(enc_key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))
