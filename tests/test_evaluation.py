"""Tests for the baseline-vs-enhanced detection benchmark.

These lock in the project's central claim -- that PrivacyShield's student-
focused additions improve detection of student IDs, unusual formats, and PII
in free text relative to a generic baseline -- WITHOUT overclaiming perfect
anonymity.
"""

from privacyshield.evaluation import (
    run_comparison,
    evaluate,
    student_benchmark,
    Score,
    LabeledExample,
    LabeledSpan,
)
from privacyshield.detection import Detector, STUDENT_ID, EMAIL


def test_enhanced_detects_student_ids_baseline_misses():
    baseline, enhanced, _ = run_comparison()
    # The generic baseline has no student-ID recognizer -> all FN.
    assert STUDENT_ID not in baseline or baseline[STUDENT_ID].tp == 0
    # The enhanced detector finds student IDs.
    assert enhanced[STUDENT_ID].tp > 0
    assert enhanced[STUDENT_ID].recall == 1.0


def test_enhanced_overall_recall_beats_baseline():
    baseline, enhanced, _ = run_comparison()
    assert enhanced["OVERALL"].recall > baseline["OVERALL"].recall


def test_enhanced_does_not_regress_email_detection():
    baseline, enhanced, _ = run_comparison()
    assert enhanced[EMAIL].recall >= baseline.get(EMAIL, Score()).recall
    assert enhanced[EMAIL].recall == 1.0


def test_negative_example_produces_no_false_positives_for_ids():
    # "No concerns this term." must not yield a student ID or email.
    det = Detector(use_ner=False)
    dets = det.detect_text("No concerns this term.")
    assert all(d.entity_type not in (STUDENT_ID, EMAIL) for d in dets)


def test_score_metrics_math():
    s = Score(tp=3, fp=1, fn=1)
    assert abs(s.precision - 0.75) < 1e-9
    assert abs(s.recall - 0.75) < 1e-9
    assert abs(s.f1 - 0.75) < 1e-9


def test_evaluate_counts_true_positive():
    ex = [LabeledExample("ID U12345678 here", [LabeledSpan(STUDENT_ID, "U12345678")])]
    scores = evaluate(Detector(use_ner=False), ex)
    assert scores[STUDENT_ID].tp == 1
    assert scores[STUDENT_ID].fn == 0


def test_benchmark_has_edge_cases():
    examples = student_benchmark()
    assert len(examples) >= 6
    # at least one negative (no spans) example present
    assert any(len(e.spans) == 0 for e in examples)
    # student IDs represented
    assert any(sp.entity_type == STUDENT_ID for e in examples for sp in e.spans)
