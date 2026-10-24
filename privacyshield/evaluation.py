"""Detection evaluation harness: default baseline vs. PrivacyShield's enhanced
detector, measured on labeled synthetic examples.

This supports the project's central, honest claim:

    "We reduce the sensitive information shared with external tools while
     preserving useful data for student research."

It does NOT claim perfect anonymity. It measures, on a small labeled set,
how PrivacyShield's student-focused additions (a custom student-ID recognizer,
column-name rules, and tuned regex for emails/phones/addresses) change
detection of the entity types that matter for student data -- especially
university student IDs, unusual formatting, and PII embedded in free-text notes.

Two detectors are compared:

* ``baseline``  -- a deliberately generic detector that stands in for an
  "out-of-the-box" setup with NO student-ID recognizer and NO column rules.
  (When Presidio/spaCy are installed, swap this for real default Presidio; see
  ``build_baseline_detector``.)
* ``enhanced``  -- PrivacyShield's full detector.

Metrics reported per entity type and overall: true positives, false positives,
false negatives, precision, recall, and F1. Precision/recall are standard
information-retrieval metrics, reported here as detection metrics -- not a
privacy guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .detection import (
    Detector,
    EMAIL_RE,
    PERSON_FALLBACK_RE,
    Detection,
    EMAIL,
    PHONE,
    ADDRESS,
    STUDENT_ID,
    PERSON,
    resolve_overlaps,
)


# ---------------------------------------------------------------------------
# Labeled example type
# ---------------------------------------------------------------------------

@dataclass
class LabeledSpan:
    entity_type: str
    text: str


@dataclass
class LabeledExample:
    """A text plus the PII values it is known to contain (gold labels)."""

    text: str
    spans: List[LabeledSpan] = field(default_factory=list)


# ---------------------------------------------------------------------------
# A generic "baseline" detector (stand-in for out-of-the-box detection)
# ---------------------------------------------------------------------------

class BaselineDetector:
    """Generic detector WITHOUT PrivacyShield's student-focused additions.

    Intentionally omits:
      - the custom student-ID recognizer (U12345678-style IDs),
      - column-name rules,
      - address detection,
    to represent a plausible out-of-the-box baseline. It keeps only generic
    email + a loose person heuristic, which is what a naive setup might catch.

    If you install Presidio + spaCy, replace this with real default Presidio
    (AnalyzerEngine with no custom recognizers) via ``build_baseline_detector``
    for an apples-to-apples comparison against the enhanced engine.
    """

    def detect_text(self, text: str) -> List[Detection]:
        out: List[Detection] = []
        for m in EMAIL_RE.finditer(text):
            out.append(Detection(EMAIL, m.start(), m.end(), m.group(), 0.9, "baseline:email"))
        # A naive person heuristic (no NER): two capitalized words.
        for m in PERSON_FALLBACK_RE.finditer(text):
            out.append(Detection(PERSON, m.start(1), m.end(1), m.group(1), 0.4, "baseline:person"))
        return resolve_overlaps(out)


def build_baseline_detector():
    """Return real default-Presidio when available, else the generic baseline.

    Real default Presidio = AnalyzerEngine with its built-in recognizers only
    (NO student-ID recognizer, NO column rules), which is the fair "before".
    """
    try:
        from presidio_analyzer import AnalyzerEngine
        import spacy  # noqa: F401

        class _PresidioBaseline:
            def __init__(self):
                self.engine = AnalyzerEngine()

            def detect_text(self, text: str) -> List[Detection]:
                mapping = {
                    "PERSON": PERSON, "EMAIL_ADDRESS": EMAIL,
                    "PHONE_NUMBER": PHONE, "LOCATION": ADDRESS,
                }
                out: List[Detection] = []
                try:
                    results = self.engine.analyze(text=text, language="en")
                except Exception:
                    return out
                for r in results:
                    et = mapping.get(r.entity_type)
                    if et:
                        out.append(Detection(et, r.start, r.end,
                                             text[r.start:r.end], float(r.score),
                                             f"presidio-default:{r.entity_type}"))
                return resolve_overlaps(out)

        return _PresidioBaseline()
    except Exception:
        return BaselineDetector()


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def _match_key(entity_type: str, text: str) -> Tuple[str, str]:
    return (entity_type, text.strip())


def evaluate(detector, examples: List[LabeledExample]) -> Dict[str, Score]:
    """Score a detector against labeled examples.

    Matching is by (entity_type, normalized text), so a detection counts as a
    true positive if it finds the right value with the right type. Partial
    span matches for the same value still count (we compare the detected text
    to the gold text after stripping), which is appropriate for tokenization.
    Per-type scores plus an ``OVERALL`` aggregate are returned.
    """
    scores: Dict[str, Score] = {}

    def s(t: str) -> Score:
        return scores.setdefault(t, Score())

    overall = s("OVERALL")

    for ex in examples:
        gold = set(_match_key(sp.entity_type, sp.text) for sp in ex.spans)
        dets = detector.detect_text(ex.text)
        pred = set(_match_key(d.entity_type, d.text) for d in dets)

        for key in pred & gold:
            s(key[0]).tp += 1
            overall.tp += 1
        for key in pred - gold:
            s(key[0]).fp += 1
            overall.fp += 1
        for key in gold - pred:
            s(key[0]).fn += 1
            overall.fn += 1

    return scores


# ---------------------------------------------------------------------------
# A labeled benchmark set focused on student data edge cases
# ---------------------------------------------------------------------------

def student_benchmark() -> List[LabeledExample]:
    """Hand-labeled synthetic examples stressing student-specific PII.

    Deliberately includes university student IDs, unusual formatting, and PII
    embedded in free-text advising notes -- the cases PrivacyShield's additions
    target and where a generic baseline is expected to miss detections.
    """
    return [
        LabeledExample(
            "Student U12345678 requested an extension.",
            [LabeledSpan(STUDENT_ID, "U12345678")],
        ),
        LabeledExample(
            "Advisee ID S00412345 is on academic probation.",
            [LabeledSpan(STUDENT_ID, "S00412345")],
        ),
        LabeledExample(
            "Contact ada.lovelace@students.example.edu or call (617) 555-0199.",
            [LabeledSpan(EMAIL, "ada.lovelace@students.example.edu"),
             LabeledSpan(PHONE, "(617) 555-0199")],
        ),
        LabeledExample(
            "Mailed transcript to 123 Maple Street regarding U87654321.",
            [LabeledSpan(ADDRESS, "123 Maple Street"),
             LabeledSpan(STUDENT_ID, "U87654321")],
        ),
        LabeledExample(
            "Left voicemail at 617-555-0100 about tuition for G9988776.",
            [LabeledSpan(PHONE, "617-555-0100"),
             LabeledSpan(STUDENT_ID, "G9988776")],
        ),
        LabeledExample(
            "No concerns this term.",
            [],  # negative example: should produce no detections
        ),
        LabeledExample(
            "Email bob@x.edu; student number U00001111 flagged for review.",
            [LabeledSpan(EMAIL, "bob@x.edu"),
             LabeledSpan(STUDENT_ID, "U00001111")],
        ),
        LabeledExample(
            "Reached +1 617 555 0123 for the capstone meeting.",
            [LabeledSpan(PHONE, "+1 617 555 0123")],
        ),
    ]


def run_comparison() -> Tuple[Dict[str, Score], Dict[str, Score], List[LabeledExample]]:
    """Run baseline vs. enhanced on the student benchmark. Returns both scores."""
    examples = student_benchmark()
    baseline = build_baseline_detector()
    enhanced = Detector(use_ner=True)
    return evaluate(baseline, examples), evaluate(enhanced, examples), examples
