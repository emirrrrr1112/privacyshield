# 🛡️ PrivacyShield

**Hackachusetts DS+X — Data Scrubbing / Tokenization challenge**

PrivacyShield detects personally identifiable information (PII) in synthetic
student datasets and replaces it with **consistent, reversible tokens**. The
original ↔ token mapping is exported under **authenticated encryption**, and a
dedicated Restore page recovers the original values when you have the key.

> ⚠️ **Important honesty note.** PrivacyShield performs *pseudonymization*, not
> anonymization. Detection is best-effort pattern matching that can miss PII or
> flag non-PII. The metrics it reports are **detection metrics for human
> review, not a validated privacy or anonymity score.** Reversible tokens plus
> retained attributes (e.g. GPA, major, year) may still re-identify people.

---

## Quick start

```bash
# 1. (recommended) create a virtual environment
python -m venv .venv && source .venv/bin/activate

# 2. install dependencies
pip install -r requirements.txt

# 3. (recommended) download a spaCy model for best free-text name detection
python -m spacy download en_core_web_lg      # or en_core_web_sm (smaller)

# 4. run the app
streamlit run app.py
```

Then open the URL Streamlit prints (default <http://localhost:8501>).

### Run without the UI

The core library is dependency-free and ships a headless demo plus a test suite:

```bash
python demo_cli.py          # full detect → tokenize → encrypt → restore → report
python -m pytest -q         # run the automated tests
```

### Generate / refresh the demo CSV

A ready-made synthetic dataset lives at `data/demo_students.csv`. Regenerate it with:

```bash
python -c "from privacyshield.synthetic import write_demo_csv; write_demo_csv('data/demo_students.csv')"
```

---

## Graceful degradation (fallbacks)

PrivacyShield is designed to run **even when the heavy ML/crypto packages can't
be installed**, with explicitly reduced coverage:

| Capability        | Preferred backend                    | Fallback (stdlib only)                               | Coverage impact |
|-------------------|--------------------------------------|------------------------------------------------------|-----------------|
| Free-text NER     | Presidio + spaCy (`en_core_web_lg`)  | Regex + a conservative capitalized-name heuristic    | Reduced recall on names/locations in prose; structured columns and emails/phones/IDs/addresses unaffected |
| Mapping encryption| AES-256-GCM (`cryptography`, AEAD)   | Encrypt-then-MAC (SHA-256 keystream + HMAC-SHA256)   | None for security properties; both are authenticated |
| DataFrame/CSV     | pandas (UI)                          | stdlib `csv` (library + tests)                       | None for core processing |

The active backend is **shown in the app sidebar and in every JSON report**, so
the reduction in coverage is always disclosed. The structured-column recognizers
(email, phone, student ID, address) and the custom `U12345678` student-ID
recognizer are **regex-based and always available**.

---

## Workflow

The UI is a four-step wizard plus a separate Restore page:

1. **Upload** — drop a CSV or click *Try demo data*; see a preview, row count,
   and column names. Synthetic demo data is clearly badged as such.
2. **Review** — per-column suggested treatment (**keep / tokenize / remove**)
   with highlighted examples and detected entity types. You confirm or change it.
3. **Tokenize** — replace detected values with tokens like `PERSON_001`,
   `EMAIL_001`, `STUDENT_ID_001`. The same value → the same token across columns
   *and* free text; different values → different tokens.
4. **Export** — original vs. processed side by side, detection/replacement
   counts, a **residual re-scan** of processed data, and downloads for the
   processed CSV, a PII-free JSON report, the **encrypted mapping**, and the
   **decryption key** (downloaded separately — never inside the mapping).

**Restore** — upload a tokenized CSV + encrypted mapping + key to recover
originals (including tokens embedded in free text). Wrong key or corrupted
mapping produces a clear error.

---

## Architecture

Reusable processing logic is fully separated from the Streamlit UI.

```
privacyshield/
├── app.py                 # Streamlit UI (thin presentation layer)
├── demo_cli.py            # headless end-to-end demo
├── requirements.txt
├── data/
│   └── demo_students.csv  # synthetic demo dataset (36 rows)
├── privacyshield/         # reusable library (no Streamlit import)
│   ├── detection.py       # column rules + regex + custom student-ID + Presidio/spaCy
│   ├── tokenization.py    # consistent, reversible, collision-safe tokens
│   ├── crypto.py          # AES-GCM / stdlib Encrypt-then-MAC authenticated encryption
│   ├── pipeline.py        # review → detect → tokenize orchestration
│   ├── restoration.py     # reverse tokenization (incl. inside free text)
│   ├── report.py          # PII-free JSON processing report
│   ├── io_utils.py        # pandas-free CSV read/write
│   └── synthetic.py       # synthetic student data generator
└── tests/                 # pytest suite
```

### Key design decisions

- **Session-consistent tokens.** A `TokenMapping` is keyed by
  `(entity_type, original_value)` so identical values share one token everywhere
  and different values never collide. New tokens are checked against both
  already-issued tokens *and* raw input strings to avoid collisions with values
  already present in the data.
- **Overlap resolution.** Overlapping detections are reduced to a
  non-overlapping set (highest confidence wins, then longer span) *before*
  replacement, and spans are spliced right-to-left so offsets stay valid.
- **Structured vs. free text.** Structured columns tokenize the whole cell by
  the column's entity type (lossless restoration); free-text columns replace
  individual spans in place.
- **Security.** The mapping is kept separate from the processed data and
  encrypted with authenticated encryption; the key is never embedded in the
  mapping file. No original values or keys are logged. Nothing is sent to
  external APIs and uploads are not persisted by default (a **Clear session**
  button wipes in-memory state).

---

## Tests

`python -m pytest -q` covers:

- consistent tokens for repeated values; unique tokens for different values;
- the empty-mapping regression (an empty mapping must not be silently discarded);
- detection of emails, phone numbers, and student IDs; free-text replacement;
- missing values preserved; non-sensitive fields preserved; `remove` drops columns;
- overlapping detections; token collisions with input values;
- encrypted export round-trip; wrong key and corrupted/tampered mapping errors;
- a full tokenize → encrypt → restore round-trip that is lossless;
- a report that provably contains no original PII.

---

## Limitations

- **Not anonymization.** Reversible by design; quasi-identifiers remain.
- **Regex-only mode** (no spaCy/Presidio) has lower recall for names and
  locations embedded in free-text prose. Single first names inside notes may
  remain and will surface in the residual re-scan for manual review.
- Phone/address patterns target common North-American formats; international
  formats may be missed.
- Detection thresholds are tuned to limit false positives; the Review step
  exists precisely because automated detection is imperfect — always review.

## Future improvements

- Support more locales (international phone/address, non-Latin names).
- Format-preserving tokenization and optional deterministic HMAC tokens for
  joinable datasets.
- Configurable per-entity policies (mask, hash, redact) and a saved policy file.
- Key management via OS keyring / KMS instead of a downloaded key file.
- Dictionary/allow-list recognizers and active-learning feedback from the Review
  step to reduce false positives over time.

---

## License

Provided as-is for the Hackachusetts DS+X hackathon. Use only with synthetic or
properly authorized data.
