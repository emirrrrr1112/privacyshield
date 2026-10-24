# 🎬 PrivacyShield — 2-Minute Demo Script

**Goal:** show the problem, demonstrate detection + tokenization, and prove
reversible restoration — in about two minutes.

---

### 0:00 – 0:20 · The problem
> "Schools share student data with researchers and vendors, but those files are
> full of PII — names, emails, phones, addresses, student IDs, and free-text
> advising notes. Redacting it by hand is slow and error-prone, and once it's
> gone you can't get it back when you legitimately need to.
>
> PrivacyShield detects that PII and swaps it for **consistent, reversible
> tokens** — and it keeps the un-swap key under encryption."

*(Sidebar is visible: point out the Detection and Encryption backends, and the
honesty note that this is pseudonymization, not anonymization.)*

---

### 0:20 – 0:45 · Upload & Review
1. Click **✨ Try demo data** → 36 synthetic rows load, badged **SYNTHETIC DEMO DATA**.
   > "Fictional data, generated locally — nothing leaves this machine."
2. Click **Continue to Review**.
3. Expand `email`, `student_id`, and `notes`.
   > "It proposes a treatment per column — keep, tokenize, or remove — and shows
   > highlighted examples. I stay in control: I can override any column. Notice
   > the free-text `notes` column is flagged for multiple entity types."

---

### 0:45 – 1:15 · Tokenize
1. Click **Tokenize now**.
2. Show the **Original vs. Processed** tables side by side.
   > "Every name becomes `PERSON_001`, every email `EMAIL_001`, student IDs
   > `STUDENT_ID_001`, and so on. The crucial part: the **same value always gets
   > the same token** — across columns *and* inside the free-text notes — so the
   > data stays analytically useful. Different values get different tokens."
3. Point to a tokenized note, e.g. `Student STUDENT_ID_004 ... call guardian at PHONE_004.`
   > "Even PII buried in prose is replaced, with the same tokens as the
   > structured columns."

---

### 1:15 – 1:40 · Export & dashboard
1. Click **Go to Export**.
2. Show the metrics and the **residual re-scan**.
   > "It re-runs detection on the *processed* data and reports what's left —
   > honestly labeled as a detection metric for review, not a privacy guarantee."
3. Point at the four download buttons.
   > "I can download the processed CSV, a **PII-free** JSON report, the
   > **encrypted mapping**, and the **decryption key** — and the key is
   > downloaded *separately*; it's never inside the mapping file."

---

### 1:40 – 2:00 · Restore (the payoff)
1. Switch to the **Restore** page in the sidebar.
2. Upload the processed CSV, the `.psmap` mapping, and the key.
3. Click **🔓 Restore** → original values reappear, including inside the notes.
   > "With the key, it's fully reversible — a lossless round-trip. Without the
   > correct key, or with a tampered mapping, it refuses and shows a clear
   > error, because the mapping is under authenticated encryption."
4. *(Optional)* paste a wrong key to show the red error.

> **Close:** "Detect, tokenize consistently, encrypt the mapping, restore on
> demand — PrivacyShield makes student data safe to share *and* recoverable."

---

### Backup: headless demo
If the UI misbehaves live, run:
```bash
python demo_cli.py
```
It prints the same detect → tokenize → encrypt → **lossless restore** → report
flow in the terminal.
