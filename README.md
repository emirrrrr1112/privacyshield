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

## Why this is useful

**Central claim:** *We reduce the sensitive information shared with external
tools while preserving useful data for student research.*

Cloud services already protect data well — for example, **Anthropic** (the
company behind the **Claude** product) encrypts stored data and connections in
transit, restricts training use of commercial/API data by default, and enforces
retention windows. Those protections secure data **in storage and transmission**
— they do **not** strip identifiers out of the content you submit. So if you
upload a raw student CSV to *any* external tool, that service still receives the
names, emails, phones, addresses, and student IDs inside it.

PrivacyShield closes that gap by running **locally, before upload**: it detects
and tokenizes PII on your machine so the data you share carries tokens instead
of real identifiers — while staying analytically useful (the same student keeps
the same token, so joins and counts still work).

> These are limitations and remaining risks of *any* upload workflow — **not** a
> claim that Anthropic or any provider has a security vulnerability. We do not
> claim to anonymize data or to outperform a provider's security system.

### The specific gaps PrivacyShield addresses

| Remaining risk when sharing student data | What PrivacyShield does |
|---|---|
| Uploading raw data hands identifiers to the external service for processing. | Detect + **tokenize locally, before upload**. |
| General detectors miss university-specific identifiers. | A **custom student-ID recognizer** (e.g. `U12345678`) + **column-name rules**. |
| Detection can miss sensitive text or flag harmless text. | A **Review screen** to confirm/override per column + a measured **baseline-vs-enhanced benchmark** (precision/recall). |
| Removing names still leaves identifying combinations (rare major + year + town). | **Keep / tokenize / remove** per column, including dropping quasi-identifiers; honest disclosure that attribute combinations can still identify people. |
| Reversible tokens can expose identities if the mapping/key leak. | **Authenticated encryption** of the mapping, with the key kept **separate** from the shared dataset. |

### Tool roles (and their limits)

PrivacyShield composes well-documented tools rather than reinventing them:

| Tool | Role in PrivacyShield | Limitation (why we add to it) |
|---|---|---|
| [**Microsoft Presidio**](https://microsoft.github.io/presidio/) | Detects sensitive entities and supports masking/replacement. | Does **not** guarantee finding all sensitive info; custom student IDs and unusual formats need our own rules. |
| **spaCy** | Named-entity recognition (people, orgs, locations) that Presidio uses in its pipeline. | Predictions depend on training/context; it is **not** a complete privacy or encryption system. |
| **Faker** *(optional)* | Could generate fictional demo/test data. | Does **not** detect sensitive info; generating fake names does **not** make a dataset anonymous. *(Our bundled generator uses the stdlib, so Faker is optional.)* |

> Our additions on top of these tools are the student-ID recognizer, column
> rules, overlap-safe tokenization, encrypted reversible mapping, a review
> workflow, and a residual re-scan — demonstrated by the benchmark below.

### Baseline vs. enhanced benchmark

`python benchmark.py` compares a **generic/default detector** against
PrivacyShield's **enhanced** detector on labeled synthetic examples that stress
student IDs, unusual formats, and PII in free-text notes:

```
entity       BASELINE                     ENHANCED
STUDENT_ID   R=0.00  (missed all)         R=1.00   ⬆
PHONE        R=0.00                        R=1.00   ⬆
ADDRESS      R=0.00                        R=1.00   ⬆
EMAIL        R=1.00                        R=1.00
OVERALL      recall 18%                    recall 100%   (+82%)
```

Precision/recall/F1 are **detection metrics for review**, not a privacy
guarantee. (When Presidio + spaCy are installed, the baseline automatically
becomes real *default Presidio* for an apples-to-apples comparison.)

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
python benchmark.py         # baseline vs. enhanced detection comparison
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
├── benchmark.py           # baseline vs. enhanced detection benchmark
├── requirements.txt
├── data/                  # synthetic demo datasets (36 → 25k rows)
│   └── demo_students*.csv
├── privacyshield/         # reusable library (no Streamlit import)
│   ├── detection.py       # column rules + regex + custom student-ID + Presidio/spaCy
│   ├── tokenization.py    # consistent, reversible, collision-safe tokens
│   ├── crypto.py          # AES-GCM / stdlib Encrypt-then-MAC authenticated encryption
│   ├── pipeline.py        # review → detect → tokenize orchestration
│   ├── restoration.py     # reverse tokenization (incl. inside free text)
│   ├── report.py          # PII-free JSON processing report
│   ├── evaluation.py      # baseline-vs-enhanced detection scoring (precision/recall/F1)
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
- a report that provably contains no original PII;
- the baseline-vs-enhanced benchmark: enhanced detects student IDs the generic
  baseline misses, improves overall recall, and does not regress email recall.

(40 tests total.)

---

## Limitations

- **Not anonymization.** Reversible by design; quasi-identifiers remain. Even
  with names removed, rare attribute combinations (e.g. an unusual major + year
  + hometown) can still identify a person; use the Review step to tokenize or
  remove such columns.
- **Detection is imperfect** and can miss PII or flag non-PII — hence the Review
  screen, the residual re-scan, and the honest benchmark rather than a claim of
  perfect detection.
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
