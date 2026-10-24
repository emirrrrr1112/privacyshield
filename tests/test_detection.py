"""Detection tests: emails, phones, student IDs, free text, overlaps."""

from privacyshield.detection import (
    Detector,
    resolve_overlaps,
    Detection,
    EMAIL,
    PHONE,
    STUDENT_ID,
    PERSON,
    ADDRESS,
)


def _types(dets):
    return sorted({d.entity_type for d in dets})


def test_detect_email():
    det = Detector(use_ner=False)
    dets = det.detect_text("reach me at ada.lovelace@example.edu please")
    assert EMAIL in _types(dets)
    assert any(d.text == "ada.lovelace@example.edu" for d in dets)


def test_detect_phone_number():
    det = Detector(use_ner=False)
    for sample in ["(617) 555-0199", "617-555-0199", "+1 617 555 0199"]:
        dets = det.detect_text(f"call {sample} now")
        assert PHONE in _types(dets), sample


def test_detect_student_id_custom_recognizer():
    det = Detector(use_ner=False)
    dets = det.detect_text("ID is U12345678 on file")
    assert STUDENT_ID in _types(dets)
    assert any(d.text == "U12345678" for d in dets)


def test_detect_address():
    det = Detector(use_ner=False)
    dets = det.detect_text("lives at 123 Maple Street now")
    assert ADDRESS in _types(dets)


def test_free_text_multiple_entities():
    det = Detector(use_ner=False)
    text = "Student U87654321 (email bob@x.edu) called (617) 555-0100."
    dets = det.detect_text(text)
    assert {STUDENT_ID, EMAIL, PHONE}.issubset(set(_types(dets)))


def test_overlap_resolution_keeps_highest_confidence_non_overlapping():
    # Two overlapping spans; higher score should win, result non-overlapping.
    a = Detection(PERSON, 0, 10, "x" * 10, 0.4, "low")
    b = Detection(EMAIL, 5, 15, "y" * 10, 0.9, "high")
    out = resolve_overlaps([a, b])
    assert len(out) == 1
    assert out[0].recognizer == "high"


def test_overlap_resolution_preserves_disjoint_spans():
    a = Detection(EMAIL, 0, 5, "aaaaa", 0.9, "e")
    b = Detection(PHONE, 10, 20, "p" * 10, 0.9, "p")
    out = resolve_overlaps([a, b])
    assert len(out) == 2
    assert [d.start for d in out] == [0, 10]


def test_empty_and_none_text():
    det = Detector(use_ner=False)
    assert det.detect_text("") == []
    assert det.detect_text(None) == []
    assert det.detect_text("   ") == []
