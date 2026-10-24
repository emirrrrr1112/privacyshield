"""End-to-end processing pipeline over a tabular dataset.

Orchestrates: review plan -> detection -> tokenization, producing a processed
dataset plus a session-scoped :class:`TokenMapping`. The pipeline is UI-free so
it can be fully unit-tested and reused as a library.

Works on a lightweight internal table representation (a list of row dicts +
ordered column list) so it does not hard-require pandas. The Streamlit layer
converts to/from pandas DataFrames at the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .detection import (
    ColumnPlan,
    ColumnTreatment,
    Detector,
    classify_column,
    is_free_text_column,
)
from .tokenization import TokenMapping, Tokenizer

# Sentinel representing a missing value. We preserve missing values exactly.
MISSING = None


def is_missing(value) -> bool:
    if value is None:
        return True
    if isinstance(value, float):
        # NaN != NaN
        return value != value
    if isinstance(value, str):
        return value.strip() == "" or value.strip().lower() in {"nan", "none"}
    return False


@dataclass
class ProcessResult:
    columns: List[str]
    original_rows: List[dict]
    processed_rows: List[dict]
    mapping: TokenMapping
    plans: Dict[str, ColumnPlan]
    detected_counts: Dict[str, int] = field(default_factory=dict)
    replaced_counts: Dict[str, int] = field(default_factory=dict)


class Pipeline:
    def __init__(self, detector: Optional[Detector] = None) -> None:
        self.detector = detector or Detector()

    # -- Review: build a suggested per-column plan --------------------------

    def suggest_plan(self, columns: List[str], rows: List[dict]) -> Dict[str, ColumnPlan]:
        """Suggest a treatment for every column based on name + sampled values.

        For free-text columns we scan content with the full detector (NER +
        regex + person fallback). For structured columns we rely on the column
        name rule and HIGH-CONFIDENCE regex only (email/phone/student_id/
        address) -- the low-confidence person fallback is deliberately NOT used
        to classify structured columns, so e.g. a "major" column of capitalized
        words is not misread as a list of people.
        """
        plans: Dict[str, ColumnPlan] = {}
        sample_n = min(len(rows), 50)
        for col in columns:
            free_text = is_free_text_column(col)
            name_type = classify_column(col)
            detected_types: List[str] = []

            sample = [r.get(col) for r in rows if not is_missing(r.get(col))][:sample_n]

            if free_text:
                for val in sample:
                    for d in self.detector.detect_text(str(val)):
                        if d.entity_type not in detected_types:
                            detected_types.append(d.entity_type)
            else:
                # High-confidence regex only (recognizer prefixed "regex:" and
                # not the person fallback).
                for val in sample:
                    for d in self.detector._regex_detections(str(val)):
                        if d.entity_type not in detected_types:
                            detected_types.append(d.entity_type)
                if name_type and name_type not in detected_types:
                    detected_types.insert(0, name_type)

            treatment = (
                ColumnTreatment.TOKENIZE if detected_types else ColumnTreatment.KEEP
            )
            plans[col] = ColumnPlan(
                name=col,
                treatment=treatment,
                detected_types=detected_types,
                is_free_text=free_text,
            )
        return plans

    @staticmethod
    def _structured_entity_type(plan: ColumnPlan, value: str) -> Optional[str]:
        """Entity type to assign to a whole structured cell, or None to keep."""
        if plan.detected_types:
            return plan.detected_types[0]
        return None

    # -- Tokenize: apply the confirmed plan ---------------------------------

    def process(
        self,
        columns: List[str],
        rows: List[dict],
        plans: Dict[str, ColumnPlan],
    ) -> ProcessResult:
        mapping = TokenMapping()
        tokenizer = Tokenizer(mapping)

        # Reserve every raw string in the input so tokens never collide with
        # values that already appear in the dataset.
        reserve_values = []
        for r in rows:
            for col in columns:
                v = r.get(col)
                if not is_missing(v):
                    reserve_values.append(str(v))
        tokenizer.reserve_input(reserve_values)

        kept_columns = [c for c in columns if plans[c].treatment != ColumnTreatment.REMOVE]

        detected_counts: Dict[str, int] = {}
        replaced_counts: Dict[str, int] = {}
        processed_rows: List[dict] = []

        for r in rows:
            new_row: dict = {}
            for col in kept_columns:
                plan = plans[col]
                value = r.get(col)

                if plan.treatment == ColumnTreatment.KEEP:
                    new_row[col] = value
                    continue

                # TOKENIZE
                if is_missing(value):
                    new_row[col] = value  # preserve missing values exactly
                    continue

                text = str(value)
                if plan.is_free_text:
                    # Free text: find and replace individual spans in place.
                    dets = self.detector.detect_text(text)
                    for d in dets:
                        detected_counts[d.entity_type] = detected_counts.get(d.entity_type, 0) + 1
                    if not dets:
                        new_row[col] = value
                        continue
                    new_row[col] = tokenizer.tokenize_spans(text, dets)
                    for d in dets:
                        replaced_counts[d.entity_type] = replaced_counts.get(d.entity_type, 0) + 1
                else:
                    # Structured cell: tokenize the WHOLE value as its entity
                    # type. The column plan carries the entity type; this keeps
                    # restoration lossless (no partial-span splicing) and avoids
                    # the low-confidence free-text person fallback.
                    etype = self._structured_entity_type(plan, text)
                    if etype is None:
                        new_row[col] = value
                        continue
                    detected_counts[etype] = detected_counts.get(etype, 0) + 1
                    new_row[col] = tokenizer.tokenize_value(etype, text)
                    replaced_counts[etype] = replaced_counts.get(etype, 0) + 1

            processed_rows.append(new_row)

        return ProcessResult(
            columns=kept_columns,
            original_rows=rows,
            processed_rows=processed_rows,
            mapping=mapping,
            plans=plans,
            detected_counts=detected_counts,
            replaced_counts=replaced_counts,
        )

    # -- Dashboard: re-scan processed data ----------------------------------

    def residual_scan(self, columns: List[str], rows: List[dict]) -> Dict[str, int]:
        """Run detection again on processed data; report remaining hits.

        Labeled in the UI as a detection metric for human review -- NOT a proof
        of anonymity.
        """
        counts: Dict[str, int] = {}
        for r in rows:
            for col in columns:
                v = r.get(col)
                if is_missing(v):
                    continue
                for d in self.detector.detect_text(str(v)):
                    counts[d.entity_type] = counts.get(d.entity_type, 0) + 1
        return counts
