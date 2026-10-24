"""Consistent, reversible tokenization.

Guarantees:
- The same (entity_type, original_value) pair always maps to the same token
  within a processing session -- across columns AND free text.
- Different values always map to different tokens.
- Tokens are collision-safe: a generated token is never a string that already
  appears anywhere in the input, and never collides with another mapping.
- Original values are preserved exactly for lossless restoration.

The mapping is kept separate from the processed data and is the only thing that
can reverse tokenization. It is never logged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .detection import Detection, TOKEN_PREFIX


@dataclass
class TokenMapping:
    """Bidirectional, session-scoped mapping between originals and tokens.

    Internally keyed by (entity_type, original_value) so that, e.g., a name and
    an address that happen to share text never collide, while identical values
    of the same type always reuse one token.
    """

    # (entity_type, original) -> token
    forward: Dict[Tuple[str, str], str] = field(default_factory=dict)
    # token -> original   (token strings are globally unique, so this is safe)
    reverse: Dict[str, str] = field(default_factory=dict)
    # per-entity running counter
    _counters: Dict[str, int] = field(default_factory=dict)
    # reserved strings that tokens must never equal (values present in input)
    _reserved: set = field(default_factory=set)

    def reserve(self, values) -> None:
        """Reserve strings that already exist in the input to avoid collisions."""
        for v in values:
            if v is not None:
                self._reserved.add(str(v))

    def token_for(self, entity_type: str, original: str) -> str:
        """Return the stable token for a value, minting a new one if needed."""
        key = (entity_type, original)
        if key in self.forward:
            return self.forward[key]

        token = self._mint(entity_type)
        self.forward[key] = token
        self.reverse[token] = original
        return token

    def _mint(self, entity_type: str) -> str:
        prefix = TOKEN_PREFIX.get(entity_type, entity_type.upper())
        while True:
            n = self._counters.get(entity_type, 0) + 1
            self._counters[entity_type] = n
            token = f"{prefix}_{n:03d}"
            # Avoid colliding with input text or an already-issued token.
            if token in self._reserved or token in self.reverse:
                continue
            return token

    # -- serialization ------------------------------------------------------

    def to_records(self) -> List[dict]:
        """Export mapping as a list of records (token -> original + type)."""
        records = []
        for (etype, original), token in self.forward.items():
            records.append(
                {"token": token, "entity_type": etype, "original": original}
            )
        records.sort(key=lambda r: r["token"])
        return records

    @classmethod
    def from_records(cls, records: List[dict]) -> "TokenMapping":
        m = cls()
        for r in records:
            etype = r["entity_type"]
            original = r["original"]
            token = r["token"]
            m.forward[(etype, original)] = token
            m.reverse[token] = original
        return m

    def __len__(self) -> int:
        return len(self.forward)


class Tokenizer:
    """Applies a :class:`TokenMapping` to text spans and whole values."""

    def __init__(self, mapping: Optional[TokenMapping] = None) -> None:
        # NB: use an explicit None check -- an empty TokenMapping is falsy
        # (``__len__`` == 0), so ``mapping or TokenMapping()`` would wrongly
        # discard a freshly-created empty mapping.
        self.mapping = mapping if mapping is not None else TokenMapping()

    def reserve_input(self, values) -> None:
        self.mapping.reserve(values)

    def tokenize_value(self, entity_type: str, original: str) -> str:
        """Tokenize an entire structured-column cell."""
        return self.mapping.token_for(entity_type, str(original))

    def tokenize_spans(self, text: str, detections: List[Detection]) -> str:
        """Replace all detected spans in ``text`` with tokens.

        Spans are replaced right-to-left so earlier offsets stay valid.
        Overlaps must already be resolved by the detector.
        """
        if not detections:
            return text
        result = text
        for d in sorted(detections, key=lambda x: x.start, reverse=True):
            token = self.mapping.token_for(d.entity_type, d.text)
            result = result[: d.start] + token + result[d.end:]
        return result
