"""PII detection engine.

Detection strategy (in priority order, highest confidence wins on overlap):

1. Custom recognizers (e.g. student IDs like U12345678) -- regex, deterministic.
2. High-signal regex (email, phone).
3. Column-name heuristics (e.g. a column named "first_name" -> PERSON).
4. Presidio / spaCy NER for free-text fields -- used when installed.

The engine degrades gracefully: if Presidio and spaCy are not available it
falls back to the pure-Python regex + heuristic recognizers. The active backend
is exposed via ``DETECTION_BACKEND`` and surfaced in the UI so detection
limitations are always disclosed to the user.

Detection is best-effort pattern matching, NOT a guarantee that all PII has
been found. Callers must present results as "detection metrics", never as a
validated anonymity score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Entity types
# ---------------------------------------------------------------------------

PERSON = "PERSON"
EMAIL = "EMAIL"
PHONE = "PHONE"
ADDRESS = "ADDRESS"
STUDENT_ID = "STUDENT_ID"

SUPPORTED_ENTITIES = [PERSON, EMAIL, PHONE, ADDRESS, STUDENT_ID]

# Human-friendly token prefixes per entity type.
TOKEN_PREFIX = {
    PERSON: "PERSON",
    EMAIL: "EMAIL",
    PHONE: "PHONE",
    ADDRESS: "ADDRESS",
    STUDENT_ID: "STUDENT_ID",
}


# ---------------------------------------------------------------------------
# Optional heavy backend detection (Presidio + spaCy)
# ---------------------------------------------------------------------------

def _detect_backend() -> str:
    try:
        import presidio_analyzer  # noqa: F401
        import spacy  # noqa: F401

        # A usable spaCy model must actually load, not just import.
        try:
            spacy.load("en_core_web_lg")
            return "presidio+spacy(en_core_web_lg)"
        except Exception:
            try:
                spacy.load("en_core_web_sm")
                return "presidio+spacy(en_core_web_sm)"
            except Exception:
                return "regex-fallback"
    except Exception:
        return "regex-fallback"


DETECTION_BACKEND = _detect_backend()


# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Detection:
    """A single detected PII span within a piece of text."""

    entity_type: str
    start: int
    end: int
    text: str
    score: float
    recognizer: str

    @property
    def length(self) -> int:
        return self.end - self.start


class ColumnTreatment(str, Enum):
    """How a column should be handled during processing."""

    KEEP = "keep"            # left untouched
    TOKENIZE = "tokenize"    # detected values replaced with tokens
    REMOVE = "remove"        # column dropped entirely


@dataclass
class ColumnPlan:
    """Per-column treatment plan produced during Review and confirmed by user."""

    name: str
    treatment: ColumnTreatment
    detected_types: List[str] = field(default_factory=list)
    is_free_text: bool = False


# ---------------------------------------------------------------------------
# Regex patterns -- deliberately conservative to limit false positives.
# ---------------------------------------------------------------------------

# Student ID: a letter prefix followed by 6-10 digits, e.g. U12345678, S00412345.
STUDENT_ID_RE = re.compile(r"\b([A-Za-z]\d{6,10})\b")

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# North-American style phone numbers with common separators.
PHONE_RE = re.compile(
    r"""(?<!\w)
    (?:\+?1[\s.\-]?)?            # optional country code
    (?:\(?\d{3}\)?[\s.\-]?)      # area code
    \d{3}[\s.\-]?\d{4}           # local number
    (?!\w)""",
    re.VERBOSE,
)

# Street address: number + street words + a street-type suffix.
STREET_SUFFIX = (
    r"(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|"
    r"Way|Place|Pl|Terrace|Ter|Circle|Cir|Square|Sq|Parkway|Pkwy|Trail|Trl)"
)
ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+(?:[A-Z][A-Za-z0-9.'\-]*\s+){0,4}" + STREET_SUFFIX + r"\.?"
    r"(?:\s*(?:Apt|Apartment|Unit|Suite|Ste|#)\s*\.?\s*\w+)?\b"
)

# Fallback person-name matcher used only for free text when NER is unavailable:
# two or more capitalized words in a row. Low confidence by design.
PERSON_FALLBACK_RE = re.compile(
    r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"
)


# ---------------------------------------------------------------------------
# Column-name heuristics
# ---------------------------------------------------------------------------

COLUMN_NAME_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?:^|_)(e[-_ ]?mail)(?:$|_)", re.I), EMAIL),
    (re.compile(r"email", re.I), EMAIL),
    (re.compile(r"phone|mobile|cell|tel(?:ephone)?", re.I), PHONE),
    (re.compile(r"address|street|addr", re.I), ADDRESS),
    (re.compile(r"student[_ ]?id|studentid|\bsid\b|\bid\b", re.I), STUDENT_ID),
    (re.compile(r"first[_ ]?name|last[_ ]?name|full[_ ]?name|\bname\b|guardian|parent",
                re.I), PERSON),
]

FREE_TEXT_HINTS = re.compile(r"note|comment|remark|description|bio|summary|text|feedback", re.I)


def classify_column(name: str) -> Optional[str]:
    """Return the most likely entity type for a column based on its name."""
    for pattern, entity in COLUMN_NAME_RULES:
        if pattern.search(name):
            return entity
    return None


def is_free_text_column(name: str) -> bool:
    return bool(FREE_TEXT_HINTS.search(name))


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class Detector:
    """Detects PII spans in free text and classifies structured columns.

    Parameters
    ----------
    use_ner:
        Attempt to use Presidio/spaCy for free-text NER when available.
        Falls back silently to regex heuristics otherwise.
    """

    def __init__(self, use_ner: bool = True) -> None:
        self.backend = DETECTION_BACKEND
        self._analyzer = None
        if use_ner and DETECTION_BACKEND.startswith("presidio"):
            self._analyzer = self._build_presidio_analyzer()

    # -- backend setup ------------------------------------------------------

    def _build_presidio_analyzer(self):
        try:
            from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern

            analyzer = AnalyzerEngine()
            # Register the custom student-ID recognizer with Presidio too.
            student_pattern = Pattern(
                name="student_id", regex=r"\b[A-Za-z]\d{6,10}\b", score=0.9
            )
            analyzer.registry.add_recognizer(
                PatternRecognizer(
                    supported_entity="STUDENT_ID", patterns=[student_pattern]
                )
            )
            return analyzer
        except Exception:
            return None

    # -- public API ---------------------------------------------------------

    def detect_text(self, text: str) -> List[Detection]:
        """Detect all PII spans in a single string, resolving overlaps."""
        if text is None:
            return []
        text = str(text)
        if not text.strip():
            return []

        raw: List[Detection] = []
        raw.extend(self._regex_detections(text))

        if self._analyzer is not None:
            raw.extend(self._presidio_detections(text))
        else:
            # Regex person fallback only when NER is unavailable.
            raw.extend(self._person_fallback(text))

        return resolve_overlaps(raw)

    def detect_value(self, value: str, expected_type: Optional[str]) -> List[Detection]:
        """Detect PII in a single structured-column cell.

        If the column classification suggests a type (e.g. an ``email`` column),
        and regex finds nothing, treat the whole non-empty cell as that entity.
        This makes structured columns robust even when a value is slightly
        malformed (e.g. a name that NER would miss).
        """
        if value is None:
            return []
        value = str(value)
        if not value.strip():
            return []

        found = self.detect_text(value)
        if found:
            return found

        if expected_type in SUPPORTED_ENTITIES:
            stripped = value.strip()
            start = value.index(stripped)
            return [
                Detection(
                    entity_type=expected_type,
                    start=start,
                    end=start + len(stripped),
                    text=stripped,
                    score=0.6,
                    recognizer="column-rule",
                )
            ]
        return []

    # -- detection strategies ----------------------------------------------

    def _regex_detections(self, text: str) -> List[Detection]:
        out: List[Detection] = []
        for m in STUDENT_ID_RE.finditer(text):
            out.append(Detection(STUDENT_ID, m.start(1), m.end(1), m.group(1),
                                  0.95, "regex:student_id"))
        for m in EMAIL_RE.finditer(text):
            out.append(Detection(EMAIL, m.start(), m.end(), m.group(),
                                  0.95, "regex:email"))
        for m in PHONE_RE.finditer(text):
            span = m.group().strip()
            start = m.start() + (len(m.group()) - len(m.group().lstrip()))
            out.append(Detection(PHONE, start, start + len(span), span,
                                  0.85, "regex:phone"))
        for m in ADDRESS_RE.finditer(text):
            out.append(Detection(ADDRESS, m.start(), m.end(), m.group(),
                                  0.8, "regex:address"))
        return out

    def _person_fallback(self, text: str) -> List[Detection]:
        out: List[Detection] = []
        for m in PERSON_FALLBACK_RE.finditer(text):
            out.append(Detection(PERSON, m.start(1), m.end(1), m.group(1),
                                  0.4, "regex:person-fallback"))
        return out

    def _presidio_detections(self, text: str) -> List[Detection]:
        out: List[Detection] = []
        try:
            results = self._analyzer.analyze(
                text=text,
                language="en",
                entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
                          "LOCATION", "STUDENT_ID"],
            )
        except Exception:
            return out

        mapping = {
            "PERSON": PERSON,
            "EMAIL_ADDRESS": EMAIL,
            "PHONE_NUMBER": PHONE,
            "LOCATION": ADDRESS,
            "STUDENT_ID": STUDENT_ID,
        }
        for r in results:
            etype = mapping.get(r.entity_type)
            if not etype:
                continue
            out.append(Detection(etype, r.start, r.end, text[r.start:r.end],
                                  float(r.score), f"presidio:{r.entity_type}"))
        return out


# ---------------------------------------------------------------------------
# Overlap resolution
# ---------------------------------------------------------------------------

def resolve_overlaps(detections: List[Detection]) -> List[Detection]:
    """Resolve overlapping spans.

    Keeps the highest-confidence span; ties are broken by the longer span, then
    by earliest start. Returns a non-overlapping list sorted by start offset.
    This prevents double-replacement and corrupted text during tokenization.
    """
    if not detections:
        return []

    ordered = sorted(
        detections,
        key=lambda d: (-d.score, -(d.length), d.start),
    )
    chosen: List[Detection] = []
    for d in ordered:
        if any(_overlaps(d, c) for c in chosen):
            continue
        chosen.append(d)
    chosen.sort(key=lambda d: d.start)
    return chosen


def _overlaps(a: Detection, b: Detection) -> bool:
    return a.start < b.end and b.start < a.end
