"""CSV I/O helpers that work with or without pandas.

The Streamlit UI uses pandas for display, but the core library and tests must
run even when pandas is unavailable (this sandbox cannot install it). These
helpers convert between CSV text/bytes and the internal (columns, rows)
representation using the stdlib ``csv`` module.
"""

from __future__ import annotations

import csv
import io
from typing import List, Tuple


def read_csv_text(text: str) -> Tuple[List[str], List[dict]]:
    """Parse CSV text into (columns, rows). Empty strings become None."""
    buf = io.StringIO(text)
    reader = csv.DictReader(buf)
    columns = list(reader.fieldnames or [])
    rows: List[dict] = []
    for raw in reader:
        row = {}
        for col in columns:
            val = raw.get(col)
            row[col] = None if (val is None or val == "") else val
        rows.append(row)
    return columns, rows


def read_csv_bytes(data: bytes) -> Tuple[List[str], List[dict]]:
    return read_csv_text(data.decode("utf-8-sig"))


def write_csv_text(columns: List[str], rows: List[dict]) -> str:
    """Serialize (columns, rows) back to CSV text. None becomes empty string."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({c: ("" if r.get(c) is None else r.get(c)) for c in columns})
    return buf.getvalue()
