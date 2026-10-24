"""End-to-end restoration round-trip and PII-free report tests."""

import json

import pytest

from privacyshield import io_utils
from privacyshield.pipeline import Pipeline
from privacyshield.restoration import Restorer
from privacyshield.crypto import (
    encrypt_mapping,
    generate_key,
    InvalidKeyError,
    CorruptedMappingError,
)
from privacyshield.report import build_report
from privacyshield.synthetic import generate


def _process():
    cols, rows = generate(n_rows=36, seed=3)
    # Serialize to CSV and back so everything is strings/None, matching the
    # real export/import flow the UI uses.
    text = io_utils.write_csv_text(cols, rows)
    cols, rows = io_utils.read_csv_text(text)
    p = Pipeline()
    plans = p.suggest_plan(cols, rows)
    res = p.process(cols, rows, plans)
    return p, cols, rows, res


def test_unchanged_export_round_trips_to_original():
    _, cols, orig_rows, res = _process()

    # processed -> CSV -> re-read (the "unchanged export")
    proc_csv = io_utils.write_csv_text(res.columns, res.processed_rows)
    pcols, prows = io_utils.read_csv_text(proc_csv)

    key = generate_key()
    blob = encrypt_mapping(res.mapping.to_records(), key)
    restorer = Restorer.from_encrypted(blob, key)
    restored = restorer.restore_rows(pcols, prows)

    for i in range(len(orig_rows)):
        for c in res.columns:
            assert restored[i].get(c) == orig_rows[i].get(c), (i, c)


def test_restore_replaces_tokens_inside_free_text():
    _, cols, orig_rows, res = _process()
    key = generate_key()
    blob = encrypt_mapping(res.mapping.to_records(), key)
    restorer = Restorer.from_encrypted(blob, key)

    # find a processed note that contains a token
    note = next(r["notes"] for r in res.processed_rows
                if r.get("notes") and "_0" in str(r.get("notes")))
    restored_note = restorer.restore_text(note)
    assert "_0" not in restored_note or restored_note != note


def test_restore_with_wrong_key_errors():
    _, cols, orig_rows, res = _process()
    key = generate_key()
    blob = encrypt_mapping(res.mapping.to_records(), key)
    with pytest.raises(InvalidKeyError):
        Restorer.from_encrypted(blob, generate_key())


def test_restore_with_corrupted_mapping_errors():
    _, cols, orig_rows, res = _process()
    key = generate_key()
    blob = bytearray(encrypt_mapping(res.mapping.to_records(), key))
    blob[2] ^= 0xFF  # corrupt the header region
    with pytest.raises((CorruptedMappingError, InvalidKeyError)):
        Restorer.from_encrypted(bytes(blob), key)


def test_report_contains_no_original_pii():
    p, cols, orig_rows, res = _process()
    residual = p.residual_scan(res.columns, res.processed_rows)
    report = build_report(res, residual)
    text = json.dumps(report)

    # No original email, phone, student id, or name should appear.
    for r in orig_rows:
        for col in ["email", "phone", "student_id", "first_name", "last_name", "address"]:
            val = r.get(col)
            if val:
                assert str(val) not in text, f"PII leak: {col}={val!r}"

    # Report must carry the pseudonymization disclaimer.
    assert "pseudonymization" in report["disclaimer"].lower()
    assert "detection metric" in report["disclaimer"].lower()


def test_report_has_expected_metrics():
    p, cols, orig_rows, res = _process()
    residual = p.residual_scan(res.columns, res.processed_rows)
    report = build_report(res, residual)
    assert report["row_count"] == len(orig_rows)
    assert report["unique_tokens_issued"] == len(res.mapping)
    assert "detected_entity_counts" in report
    assert "residual_detections_on_processed_data" in report
