"""Print a baseline-vs-enhanced detection comparison on labeled student data.

Usage:
    python benchmark.py

Demonstrates the project's central, honest claim: PrivacyShield's student-
focused additions (custom student-ID recognizer, column rules, tuned regex,
and optional Presidio/spaCy NER) improve detection of the PII that matters for
student datasets, especially university student IDs, unusual formats, and PII
inside free-text notes. Metrics are detection metrics (precision/recall/F1),
NOT a guarantee of anonymity.
"""

from __future__ import annotations

from privacyshield.detection import DETECTION_BACKEND
from privacyshield.evaluation import run_comparison


def _fmt(score) -> str:
    return (f"P={score.precision:5.2f}  R={score.recall:5.2f}  F1={score.f1:5.2f}  "
            f"(tp={score.tp} fp={score.fp} fn={score.fn})")


def main() -> None:
    print("=" * 72)
    print("PrivacyShield — detection benchmark: baseline vs. enhanced")
    print("=" * 72)
    print(f"Enhanced detection backend: {DETECTION_BACKEND}\n")

    baseline, enhanced, examples = run_comparison()
    print(f"Labeled examples: {len(examples)} "
          f"(student IDs, unusual formats, free-text notes, 1 negative)\n")

    types = sorted(set(baseline) | set(enhanced))
    # OVERALL last.
    types = [t for t in types if t != "OVERALL"] + ["OVERALL"]

    header = f"{'entity':<12} {'BASELINE':<40} {'ENHANCED':<40}"
    print(header)
    print("-" * len(header))
    for t in types:
        b = baseline.get(t)
        e = enhanced.get(t)
        b_str = _fmt(b) if b else "—"
        e_str = _fmt(e) if e else "—"
        mark = ""
        if b and e and e.recall > b.recall:
            mark = "  ⬆ recall"
        print(f"{t:<12} {b_str:<40} {e_str:<40}{mark}")

    print()
    bo, eo = baseline["OVERALL"], enhanced["OVERALL"]
    print("Summary:")
    print(f"  Baseline  overall recall: {bo.recall:.0%}  precision: {bo.precision:.0%}")
    print(f"  Enhanced  overall recall: {eo.recall:.0%}  precision: {eo.precision:.0%}")
    delta = eo.recall - bo.recall
    print(f"  Recall improvement: {delta:+.0%} "
          f"(more sensitive values detected before sharing)")
    print()
    print("Note: precision/recall are DETECTION metrics for review, not a")
    print("proof of anonymity. Reversible tokenization is pseudonymization;")
    print("retained attribute combinations may still identify individuals.")


if __name__ == "__main__":
    main()
