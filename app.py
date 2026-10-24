"""PrivacyShield -- Streamlit UI.

A four-step workflow (Upload -> Review -> Tokenize -> Export) plus a separate
Restore page. All heavy lifting is delegated to the ``privacyshield`` package
so this file stays a thin presentation layer.

Run:  streamlit run app.py
"""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from privacyshield import (
    Pipeline,
    Detector,
    generate_key,
    encrypt_mapping,
    DETECTION_BACKEND,
    CRYPTO_BACKEND,
)
from privacyshield.detection import ColumnTreatment
from privacyshield.io_utils import read_csv_bytes, write_csv_text
from privacyshield.report import build_report, DISCLAIMER
from privacyshield.restoration import Restorer
from privacyshield.crypto import InvalidKeyError, CorruptedMappingError
from privacyshield.synthetic import generate


st.set_page_config(
    page_title="PrivacyShield",
    page_icon="🛡️",
    layout="wide",
)

STEPS = ["1 · Upload", "2 · Review", "3 · Tokenize", "4 · Export"]


# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------

def _init_state():
    ss = st.session_state
    ss.setdefault("step", 0)
    ss.setdefault("columns", None)
    ss.setdefault("rows", None)
    ss.setdefault("source", None)       # "demo" or "upload"
    ss.setdefault("plans", None)
    ss.setdefault("result", None)
    ss.setdefault("key", None)


def clear_session():
    for k in ["step", "columns", "rows", "source", "plans", "result", "key"]:
        st.session_state.pop(k, None)
    _init_state()


def _df(columns, rows):
    return pd.DataFrame([{c: r.get(c) for c in columns} for r in rows], columns=columns)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def sidebar():
    with st.sidebar:
        st.markdown("## 🛡️ PrivacyShield")
        st.caption("PII detection & reversible tokenization for student data")

        page = st.radio("Page", ["Process", "Restore"], key="page")

        st.divider()
        st.markdown("**Active backends**")
        st.markdown(f"- Detection: `{DETECTION_BACKEND}`")
        st.markdown(f"- Encryption: `{CRYPTO_BACKEND}`")
        if DETECTION_BACKEND == "regex-fallback":
            st.warning(
                "Running in regex-only mode (Presidio/spaCy not installed). "
                "Free-text name detection is reduced. See README.",
                icon="⚠️",
            )

        st.divider()
        if st.button("🧹 Clear session", use_container_width=True):
            clear_session()
            st.rerun()

        st.divider()
        st.caption(
            "Your data stays local. Nothing is uploaded to external APIs and "
            "datasets are not persisted by default."
        )
    return page


# ---------------------------------------------------------------------------
# Progress header
# ---------------------------------------------------------------------------

def progress_header():
    cols = st.columns(len(STEPS))
    for i, (col, label) in enumerate(zip(cols, STEPS)):
        with col:
            if i < st.session_state.step:
                st.success(label)
            elif i == st.session_state.step:
                st.info(f"**{label}**")
            else:
                st.caption(label)


# ---------------------------------------------------------------------------
# Step 1: Upload
# ---------------------------------------------------------------------------

def step_upload():
    st.subheader("Step 1 — Upload a dataset")
    st.write(
        "Upload a CSV of student records, or load the built-in **synthetic** "
        "demo dataset to explore the tool safely."
    )

    c1, c2 = st.columns(2)
    with c1:
        up = st.file_uploader("Upload CSV", type=["csv"])
        if up is not None:
            try:
                data = up.read()
                columns, rows = read_csv_bytes(data)
                if not columns:
                    st.error("That file has no columns. Is it a valid CSV?")
                else:
                    st.session_state.columns = columns
                    st.session_state.rows = rows
                    st.session_state.source = "upload"
                    st.success(f"Loaded {len(rows)} rows, {len(columns)} columns.")
            except Exception as exc:  # malformed file
                st.error(f"Could not read that file: {exc}")

    with c2:
        st.markdown("**Synthetic demo data**")
        st.caption("Fictional, generated locally. Clearly labeled as demo.")
        if st.button("✨ Try demo data", use_container_width=True):
            columns, rows = generate(n_rows=36, seed=7)
            st.session_state.columns = columns
            st.session_state.rows = rows
            st.session_state.source = "demo"
            st.success(f"Loaded synthetic demo dataset: {len(rows)} rows.")

        # Download the synthetic dataset
        columns, rows = generate(n_rows=36, seed=7)
        st.download_button(
            "⬇️ Download synthetic demo CSV",
            data=write_csv_text(columns, rows),
            file_name="privacyshield_demo_students.csv",
            mime="text/csv",
            use_container_width=True,
        )

    if st.session_state.rows is not None:
        src = st.session_state.source
        badge = "🧪 SYNTHETIC DEMO DATA" if src == "demo" else "📄 YOUR UPLOAD"
        st.markdown(f"#### Preview — {badge}")
        c1, c2 = st.columns(2)
        c1.metric("Rows", len(st.session_state.rows))
        c2.metric("Columns", len(st.session_state.columns))
        st.dataframe(
            _df(st.session_state.columns, st.session_state.rows).head(20),
            use_container_width=True,
        )
        st.caption("Columns: " + ", ".join(st.session_state.columns))

        if st.button("Continue to Review →", type="primary"):
            with st.spinner("Scanning columns for PII…"):
                pipeline = Pipeline()
                st.session_state.plans = pipeline.suggest_plan(
                    st.session_state.columns, st.session_state.rows
                )
            st.session_state.step = 1
            st.rerun()


# ---------------------------------------------------------------------------
# Step 2: Review
# ---------------------------------------------------------------------------

def step_review():
    st.subheader("Step 2 — Review detections & choose treatment")
    st.info(
        "Detection is **best-effort pattern matching** and may miss PII or flag "
        "non-PII. Review each column and confirm how it should be handled.",
        icon="ℹ️",
    )

    plans = st.session_state.plans
    columns = st.session_state.columns
    rows = st.session_state.rows
    detector = Detector()

    for col in columns:
        plan = plans[col]
        with st.expander(
            f"**{col}**  —  suggested: `{plan.treatment.value}`"
            + (f"  ·  types: {', '.join(plan.detected_types)}" if plan.detected_types else ""),
            expanded=bool(plan.detected_types),
        ):
            cc1, cc2 = st.columns([1, 2])
            with cc1:
                choice = st.radio(
                    "Treatment",
                    options=[t.value for t in ColumnTreatment],
                    index=[t.value for t in ColumnTreatment].index(plan.treatment.value),
                    key=f"treat_{col}",
                    horizontal=False,
                )
                plan.treatment = ColumnTreatment(choice)
                st.caption("Free-text field" if plan.is_free_text else "Structured field")

            with cc2:
                st.markdown("**Highlighted examples**")
                shown = 0
                for r in rows:
                    v = r.get(col)
                    if v is None or str(v).strip() == "":
                        continue
                    dets = (detector.detect_text(str(v)) if plan.is_free_text
                            else detector._regex_detections(str(v)))
                    if dets or plan.detected_types:
                        preview = str(v)
                        if len(preview) > 120:
                            preview = preview[:120] + "…"
                        st.code(preview, language=None)
                        shown += 1
                    if shown >= 3:
                        break
                if shown == 0:
                    st.caption("No PII patterns detected in sample.")

    # Aggregate detected entity counts across the sample
    st.divider()
    st.markdown("#### Detected entity types (sampled)")
    agg = {}
    for col in columns:
        for t in plans[col].detected_types:
            agg[t] = agg.get(t, 0) + 1
    if agg:
        st.dataframe(
            pd.DataFrame(
                [{"entity_type": k, "columns_flagged": v} for k, v in agg.items()]
            ),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.caption("No entity types flagged.")

    c1, c2 = st.columns(2)
    if c1.button("← Back to Upload"):
        st.session_state.step = 0
        st.rerun()
    if c2.button("Tokenize now →", type="primary"):
        st.session_state.step = 2
        st.rerun()


# ---------------------------------------------------------------------------
# Step 3: Tokenize
# ---------------------------------------------------------------------------

def step_tokenize():
    st.subheader("Step 3 — Tokenize")
    with st.spinner("Detecting and replacing PII with consistent tokens…"):
        pipeline = Pipeline()
        result = pipeline.process(
            st.session_state.columns, st.session_state.rows, st.session_state.plans
        )
        st.session_state.result = result
        if st.session_state.key is None:
            st.session_state.key = generate_key()

    st.success(
        f"Done. Issued {len(result.mapping)} unique tokens across "
        f"{len(result.columns)} columns."
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Original**")
        st.dataframe(_df(result.columns, result.original_rows).head(15),
                     use_container_width=True)
    with c2:
        st.markdown("**Processed (tokenized)**")
        st.dataframe(_df(result.columns, result.processed_rows).head(15),
                     use_container_width=True)

    st.markdown("#### Replaced entity counts")
    if result.replaced_counts:
        st.dataframe(
            pd.DataFrame(
                [{"entity_type": k, "replaced": v}
                 for k, v in sorted(result.replaced_counts.items())]
            ),
            use_container_width=True,
            hide_index=True,
        )

    c1, c2 = st.columns(2)
    if c1.button("← Back to Review"):
        st.session_state.step = 1
        st.rerun()
    if c2.button("Go to Export →", type="primary"):
        st.session_state.step = 3
        st.rerun()


# ---------------------------------------------------------------------------
# Step 4: Export + dashboard
# ---------------------------------------------------------------------------

def step_export():
    st.subheader("Step 4 — Results & Export")
    result = st.session_state.result
    if result is None:
        st.warning("Nothing processed yet.")
        return

    pipeline = Pipeline()
    residual = pipeline.residual_scan(result.columns, result.processed_rows)

    st.warning(DISCLAIMER, icon="⚠️")

    # Dashboard metrics
    m1, m2, m3 = st.columns(3)
    m1.metric("Rows processed", len(result.original_rows))
    m2.metric("Unique tokens", len(result.mapping))
    m3.metric("Entity types replaced", len(result.replaced_counts))

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Detected / replaced by type**")
        st.dataframe(
            pd.DataFrame(
                [{"entity_type": k,
                  "detected": result.detected_counts.get(k, 0),
                  "replaced": result.replaced_counts.get(k, 0)}
                 for k in sorted(set(result.detected_counts) | set(result.replaced_counts))]
            ),
            use_container_width=True, hide_index=True,
        )
    with c2:
        st.markdown("**Residual detections on processed data**")
        st.caption("Detection metric for human review — NOT a proof of anonymity.")
        if residual:
            st.dataframe(
                pd.DataFrame([{"entity_type": k, "remaining": v}
                              for k, v in sorted(residual.items())]),
                use_container_width=True, hide_index=True,
            )
        else:
            st.success("No residual PII patterns detected in processed data.")

    st.divider()
    st.markdown("### Downloads")

    processed_csv = write_csv_text(result.columns, result.processed_rows)
    report = build_report(result, residual)
    key = st.session_state.key
    encrypted = encrypt_mapping(result.mapping.to_records(), key)

    d1, d2 = st.columns(2)
    with d1:
        st.download_button(
            "⬇️ Processed CSV (no original PII)",
            data=processed_csv, file_name="processed.csv",
            mime="text/csv", use_container_width=True,
        )
        st.download_button(
            "⬇️ Processing report (JSON, PII-free)",
            data=json.dumps(report, indent=2),
            file_name="processing_report.json",
            mime="application/json", use_container_width=True,
        )
    with d2:
        st.download_button(
            "🔐 Encrypted mapping (.psmap)",
            data=encrypted, file_name="mapping.psmap",
            mime="application/octet-stream", use_container_width=True,
        )
        st.download_button(
            "🔑 Decryption key (keep separate!)",
            data=key, file_name="mapping.key",
            mime="text/plain", use_container_width=True,
        )
        st.caption("The key is **never** stored in the mapping file. "
                   "Store them separately.")

    if st.button("← Back to Tokenize"):
        st.session_state.step = 2
        st.rerun()


# ---------------------------------------------------------------------------
# Restore page
# ---------------------------------------------------------------------------

def page_restore():
    st.subheader("Restore — reverse tokenization")
    st.write(
        "Upload a tokenized CSV, the encrypted mapping (`.psmap`), and the "
        "decryption key to recover the original values."
    )

    csv_file = st.file_uploader("Tokenized CSV", type=["csv"], key="r_csv")
    map_file = st.file_uploader("Encrypted mapping (.psmap)",
                                type=["psmap", "bin", "dat"], key="r_map")
    key_input_mode = st.radio("Decryption key", ["Upload key file", "Paste key"],
                              horizontal=True)
    key_val = None
    if key_input_mode == "Upload key file":
        key_file = st.file_uploader("Key file", type=["key", "txt"], key="r_key")
        if key_file is not None:
            key_val = key_file.read().decode("utf-8").strip()
    else:
        key_val = st.text_input("Paste decryption key", type="password").strip() or None

    if st.button("🔓 Restore", type="primary"):
        if not (csv_file and map_file and key_val):
            st.error("Please provide the CSV, the encrypted mapping, and the key.")
            return
        try:
            columns, rows = read_csv_bytes(csv_file.read())
            restorer = Restorer.from_encrypted(map_file.read(), key_val)
        except InvalidKeyError:
            st.error("❌ Incorrect decryption key. Restoration aborted.")
            return
        except CorruptedMappingError:
            st.error("❌ The mapping file is corrupted or not a PrivacyShield mapping.")
            return
        except Exception as exc:
            st.error(f"❌ Could not restore: {exc}")
            return

        restored = restorer.restore_rows(columns, rows)
        st.success("Restored successfully.")
        st.dataframe(_df(columns, restored).head(25), use_container_width=True)
        st.download_button(
            "⬇️ Download restored CSV",
            data=write_csv_text(columns, restored),
            file_name="restored.csv", mime="text/csv",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    _init_state()
    page = sidebar()

    st.title("🛡️ PrivacyShield")
    st.caption("Detect PII in synthetic student data and replace it with "
               "consistent, reversible tokens.")

    if page == "Restore":
        page_restore()
        return

    progress_header()
    st.divider()

    step = st.session_state.step
    if step == 0:
        step_upload()
    elif step == 1:
        step_review()
    elif step == 2:
        step_tokenize()
    elif step == 3:
        step_export()


if __name__ == "__main__":
    main()
