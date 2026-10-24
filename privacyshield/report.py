"""Processing report generation.

Produces a JSON-serializable report describing a processing run. The report is
PII-safe by construction: it contains ONLY aggregate counts, column treatments,
backend metadata, and clearly-labeled detection metrics. It never includes any
original value, token-to-original mapping, or decryption key.
"""

from __future__ import annotations

import datetime as _dt
from typing import Dict

from .detection import DETECTION_BACKEND
from .crypto import CRYPTO_BACKEND
from .pipeline import ProcessResult


DISCLAIMER = (
    "Reversible tokenization is PSEUDONYMIZATION, not anonymization. Retained "
    "attributes may still identify individuals, and detection is best-effort "
    "pattern matching that may miss PII or flag non-PII. The counts below are "
    "detection metrics for human review, not a validated privacy guarantee."
)


def build_report(result: ProcessResult, residual_counts: Dict[str, int]) -> dict:
    """Build a PII-free processing report dictionary."""
    plans = {
        name: {
            "treatment": plan.treatment.value,
            "detected_types": list(plan.detected_types),
            "is_free_text": plan.is_free_text,
        }
        for name, plan in result.plans.items()
    }

    report = {
        "tool": "PrivacyShield",
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "detection_backend": DETECTION_BACKEND,
        "crypto_backend": CRYPTO_BACKEND,
        "row_count": len(result.original_rows),
        "input_columns": list(result.plans.keys()),
        "output_columns": list(result.columns),
        "removed_columns": [
            name for name, p in result.plans.items()
            if p.treatment.value == "remove"
        ],
        "column_plans": plans,
        "detected_entity_counts": dict(result.detected_counts),
        "replaced_entity_counts": dict(result.replaced_counts),
        "unique_tokens_issued": len(result.mapping),
        "residual_detections_on_processed_data": dict(residual_counts),
        "disclaimer": DISCLAIMER,
    }
    return report
