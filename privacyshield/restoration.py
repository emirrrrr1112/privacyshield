"""Restore original values from a tokenized dataset + encrypted mapping.

Restoration reverses tokenization using the decrypted mapping. It handles both
whole-cell tokens (structured columns) and tokens embedded inside free text.

An unchanged tokenized export round-trips exactly back to the original field
values. Wrong keys and corrupted mappings surface as clear errors (raised by
the crypto layer) rather than silent, partial restoration.
"""

from __future__ import annotations

import re
from typing import List

from .crypto import decrypt_mapping
from .tokenization import TokenMapping
from .pipeline import is_missing


# Matches any PrivacyShield-style token, e.g. PERSON_001, STUDENT_ID_017.
TOKEN_RE = re.compile(r"\b[A-Z][A-Z_]*_\d{3,}\b")


class Restorer:
    def __init__(self, mapping: TokenMapping) -> None:
        self.mapping = mapping

    @classmethod
    def from_encrypted(cls, blob: bytes, key: str) -> "Restorer":
        """Build a Restorer from an encrypted mapping blob + key.

        Raises ``InvalidKeyError`` / ``CorruptedMappingError`` on failure.
        """
        records = decrypt_mapping(blob, key)
        if not isinstance(records, list):
            from .crypto import CorruptedMappingError
            raise CorruptedMappingError("Mapping payload has an unexpected shape.")
        return cls(TokenMapping.from_records(records))

    def restore_text(self, text: str) -> str:
        """Replace every known token in ``text`` with its original value."""
        reverse = self.mapping.reverse

        def _sub(m: re.Match) -> str:
            token = m.group(0)
            return reverse.get(token, token)  # unknown tokens left as-is

        return TOKEN_RE.sub(_sub, text)

    def restore_value(self, value):
        if is_missing(value):
            return value
        return self.restore_text(str(value))

    def restore_rows(self, columns: List[str], rows: List[dict]) -> List[dict]:
        out: List[dict] = []
        for r in rows:
            new_row = {}
            for col in columns:
                new_row[col] = self.restore_value(r.get(col))
            out.append(new_row)
        return out
