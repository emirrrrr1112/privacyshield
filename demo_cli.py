"""Headless end-to-end demo of the PrivacyShield library.

Runs the full pipeline WITHOUT Streamlit so the core workflow can be verified
anywhere (including environments where the UI deps are not installed):

    detect -> tokenize -> encrypt mapping -> restore -> report

Usage:
    python demo_cli.py
"""

from __future__ import annotations

import json
import os
import tempfile

from privacyshield import io_utils
from privacyshield.pipeline import Pipeline
from privacyshield.restoration import Restorer
from privacyshield.crypto import encrypt_mapping, generate_key, CRYPTO_BACKEND
from privacyshield.report import build_report
from privacyshield.detection import DETECTION_BACKEND
from privacyshield.synthetic import generate


def main() -> None:
    print("=" * 68)
    print("PrivacyShield — headless end-to-end demo")
    print("=" * 68)
    print(f"Detection backend : {DETECTION_BACKEND}")
    print(f"Crypto backend    : {CRYPTO_BACKEND}\n")

    # 1. Load synthetic data (through CSV, like the UI would).
    columns, rows = generate(n_rows=36, seed=7)
    csv_text = io_utils.write_csv_text(columns, rows)
    columns, rows = io_utils.read_csv_text(csv_text)
    print(f"Loaded synthetic dataset: {len(rows)} rows, {len(columns)} columns")

    # 2. Review + tokenize.
    pipeline = Pipeline()
    plans = pipeline.suggest_plan(columns, rows)
    print("\nColumn plan:")
    for c in columns:
        p = plans[c]
        print(f"  {c:16} -> {p.treatment.value:9} {p.detected_types}")

    result = pipeline.process(columns, rows, plans)
    print(f"\nReplaced counts : {result.replaced_counts}")
    print(f"Unique tokens   : {len(result.mapping)}")

    print("\nExample tokenized free-text notes:")
    shown = 0
    for r in result.processed_rows:
        note = r.get("notes")
        if note and "_0" in str(note):
            print(f"  • {note}")
            shown += 1
        if shown >= 3:
            break

    # 3. Encrypt the mapping.
    key = generate_key()
    blob = encrypt_mapping(result.mapping.to_records(), key)
    print(f"\nEncrypted mapping: {len(blob)} bytes (key stored separately)")

    # 4. Restore and verify a lossless round-trip through CSV.
    proc_csv = io_utils.write_csv_text(result.columns, result.processed_rows)
    pcols, prows = io_utils.read_csv_text(proc_csv)
    restorer = Restorer.from_encrypted(blob, key)
    restored = restorer.restore_rows(pcols, prows)

    orig_cols, orig_rows = io_utils.read_csv_text(csv_text)
    mism = sum(
        1
        for i in range(len(orig_rows))
        for c in result.columns
        if restored[i].get(c) != orig_rows[i].get(c)
    )
    print(f"Round-trip restore: {'LOSSLESS ✅' if mism == 0 else f'{mism} MISMATCHES ❌'}")

    # 5. PII-free report.
    residual = pipeline.residual_scan(result.columns, result.processed_rows)
    report = build_report(result, residual)
    print(f"\nResidual detections on processed data: {residual}")
    print("Report keys:", list(report.keys()))

    # Write artifacts to a temp dir for inspection.
    out = tempfile.mkdtemp(prefix="privacyshield_demo_")
    with open(os.path.join(out, "processed.csv"), "w") as fh:
        fh.write(proc_csv)
    with open(os.path.join(out, "mapping.psmap"), "wb") as fh:
        fh.write(blob)
    with open(os.path.join(out, "mapping.key"), "w") as fh:
        fh.write(key)
    with open(os.path.join(out, "processing_report.json"), "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nArtifacts written to: {out}")
    print("Done.")


if __name__ == "__main__":
    main()
