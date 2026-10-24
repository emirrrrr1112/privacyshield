"""Synthetic student dataset generator.

Produces a clearly-labeled, entirely fictional dataset for demos and tests.
Characteristics required by the challenge:
- >= 30 rows
- repeated identities (same student appears in multiple rows)
- missing values in several columns
- free-text ``notes`` fields containing embedded PII
- a mix of PII (name, email, phone, address, student_id) and non-PII (gpa,
  enrollment_year, major)

No external PII is used. Faker is NOT required; generation uses only stdlib so
it runs anywhere.
"""

from __future__ import annotations

import random
from typing import List, Tuple

FIRST = [
    "Alice", "Marcus", "Priya", "Diego", "Sophie", "Liang", "Amara", "Noah",
    "Fatima", "Oscar", "Hana", "Ivan", "Leila", "Mateo", "Yuki", "Aisha",
    "Owen", "Nadia", "Kofi", "Elena", "Rohan", "Mia", "Tariq", "Grace",
    "Hassan", "Clara", "Jamal", "Ingrid", "Santiago", "Wen", "Zara", "Lucas",
    "Freya", "Omar", "Lucia", "Kenji", "Nia", "Paulo", "Sana", "Theo",
    "Amelia", "Dev", "Chloe", "Rami", "Esther", "Finn", "Maya", "Bruno",
    "Layla", "Sven", "Keiko", "Andre", "Simone", "Yusuf", "Petra", "Hugo",
]
LAST = [
    "Nguyen", "Johnson", "Patel", "Garcia", "Muller", "Chen", "Okafor",
    "Smith", "Rahman", "Lindqvist", "Suzuki", "Petrov", "Kim", "Rossi",
    "Andersson", "Haddad", "Silva", "Nakamura", "Olsen", "Dubois", "Mbeki",
    "Novak", "Reyes", "Fischer", "Costa", "Ahmed", "Larsson", "Mori",
    "Ivanov", "Santos", "Khan", "Weber", "Moreau", "Yamamoto", "Diallo",
    "Romano", "Jensen", "Park", "Hoffmann", "Ferreira", "Tanaka", "Abebe",
    "Kowalski", "Mendez", "Lindberg", "Osei", "Vargas", "Schmidt", "Lopez",
    "Takahashi",
]
STREETS = [
    "Maple Street", "Oak Avenue", "Birch Lane", "Elm Road", "Cedar Drive",
    "Pine Court", "Willow Way", "Spruce Boulevard", "Chestnut Street",
    "Aspen Terrace", "Magnolia Drive", "Sycamore Lane", "Juniper Court",
    "Linden Avenue", "Poplar Road", "Hawthorn Way", "Dogwood Circle",
    "Redwood Place", "Beech Street", "Walnut Avenue",
]
CITIES = [
    "Cambridge", "Worcester", "Lowell", "Amherst", "Springfield", "Boston",
    "Somerville", "Medford", "Newton", "Quincy", "Brookline", "Waltham",
]
MAJORS = ["Data Science", "Biology", "Economics", "Computer Science",
          "History", "Mechanical Engineering", "Psychology"]

NOTE_TEMPLATES = [
    "Met with {first} {last} about the capstone; follow up at {email}.",
    "Student {sid} requested an extension; call guardian at {phone}.",
    "{first} moved to {address}; update records.",
    "Advising note: {first} {last} is excelling, recommend TA role.",
    "Left voicemail for {first} at {phone} regarding tuition.",
    "No concerns this term.",
    "{first} {last} reached out via {email} about the DS+X club.",
]


def _student(rng: random.Random, idx: int) -> dict:
    first = rng.choice(FIRST)
    last = rng.choice(LAST)
    sid = f"U{rng.randint(10_000_000, 99_999_999)}"
    email = f"{first.lower()}.{last.lower()}@students.example.edu"
    phone = f"({rng.randint(200,989)}) {rng.randint(200,989)}-{rng.randint(1000,9999)}"
    num = rng.randint(1, 999)
    address = f"{num} {rng.choice(STREETS)}, {rng.choice(CITIES)}, MA"
    return {
        "first_name": first,
        "last_name": last,
        "student_id": sid,
        "email": email,
        "phone": phone,
        "address": address,
    }


def generate(n_rows: int = 36, seed: int = 7) -> Tuple[List[str], List[dict]]:
    rng = random.Random(seed)
    columns = [
        "student_id", "first_name", "last_name", "email", "phone",
        "address", "major", "enrollment_year", "gpa", "notes",
    ]

    # Build a pool of distinct identities, then repeat some to create
    # recurring identities across rows.
    pool = [_student(rng, i) for i in range(max(8, n_rows // 3))]

    rows: List[dict] = []
    for _ in range(n_rows):
        s = rng.choice(pool)  # repetition -> recurring identities
        note_tpl = rng.choice(NOTE_TEMPLATES)
        note = note_tpl.format(
            first=s["first_name"], last=s["last_name"], email=s["email"],
            phone=s["phone"], address=s["address"], sid=s["student_id"],
        )

        row = {
            "student_id": s["student_id"],
            "first_name": s["first_name"],
            "last_name": s["last_name"],
            "email": s["email"],
            "phone": s["phone"],
            "address": s["address"],
            "major": rng.choice(MAJORS),
            "enrollment_year": rng.choice([2021, 2022, 2023, 2024]),
            "gpa": round(rng.uniform(2.0, 4.0), 2),
            "notes": note,
        }

        # Inject missing values at random into a few columns.
        for col in ["phone", "address", "gpa", "notes", "email"]:
            if rng.random() < 0.12:
                row[col] = None

        rows.append(row)

    return columns, rows


def write_demo_csv(path: str, n_rows: int = 36, seed: int = 7) -> str:
    from .io_utils import write_csv_text

    columns, rows = generate(n_rows=n_rows, seed=seed)
    text = write_csv_text(columns, rows)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return text
