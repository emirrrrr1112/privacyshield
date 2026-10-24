"""Pipeline tests: missing values, preserved non-sensitive fields, free text."""

from privacyshield.pipeline import Pipeline, is_missing
from privacyshield.detection import ColumnTreatment


def _rows():
    cols = ["student_id", "name", "email", "gpa", "notes"]
    rows = [
        {"student_id": "U10000001", "name": "Ada", "email": "ada@x.edu",
         "gpa": "3.9", "notes": "Call U10000001 at ada@x.edu."},
        {"student_id": "U10000002", "name": "Bo", "email": None,
         "gpa": "3.1", "notes": None},
        {"student_id": "U10000001", "name": "Ada", "email": "ada@x.edu",
         "gpa": None, "notes": "No concerns."},
    ]
    return cols, rows


def test_missing_values_are_preserved():
    cols, rows = _rows()
    p = Pipeline()
    plans = p.suggest_plan(cols, rows)
    res = p.process(cols, rows, plans)
    # email None stays None
    assert res.processed_rows[1]["email"] is None
    assert res.processed_rows[1]["notes"] is None
    assert res.processed_rows[2]["gpa"] is None


def test_non_sensitive_column_preserved():
    cols, rows = _rows()
    p = Pipeline()
    plans = p.suggest_plan(cols, rows)
    assert plans["gpa"].treatment == ColumnTreatment.KEEP
    res = p.process(cols, rows, plans)
    assert res.processed_rows[0]["gpa"] == "3.9"


def test_free_text_tokens_consistent_with_structured():
    cols, rows = _rows()
    p = Pipeline()
    plans = p.suggest_plan(cols, rows)
    res = p.process(cols, rows, plans)
    # The student_id token in the structured column must equal the one inside
    # the free-text note for the same row.
    sid_token = res.processed_rows[0]["student_id"]
    assert sid_token in res.processed_rows[0]["notes"]


def test_remove_treatment_drops_column():
    cols, rows = _rows()
    p = Pipeline()
    plans = p.suggest_plan(cols, rows)
    plans["gpa"].treatment = ColumnTreatment.REMOVE
    res = p.process(cols, rows, plans)
    assert "gpa" not in res.columns
    assert all("gpa" not in r for r in res.processed_rows)


def test_repeated_identity_shares_token():
    cols, rows = _rows()
    p = Pipeline()
    plans = p.suggest_plan(cols, rows)
    res = p.process(cols, rows, plans)
    # rows 0 and 2 are the same student
    assert res.processed_rows[0]["student_id"] == res.processed_rows[2]["student_id"]
    assert res.processed_rows[0]["email"] == res.processed_rows[2]["email"]


def test_is_missing_helper():
    assert is_missing(None)
    assert is_missing("")
    assert is_missing("   ")
    assert is_missing(float("nan"))
    assert not is_missing("x")
    assert not is_missing(0)
