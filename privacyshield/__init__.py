"""PrivacyShield: reusable PII detection, tokenization, encrypted mapping,
and restoration for synthetic student datasets.

All processing logic lives in this package and is fully decoupled from the
Streamlit UI so it can be unit-tested and reused independently.
"""

from .detection import (
    Detector,
    Detection,
    ColumnTreatment,
    DETECTION_BACKEND,
)
from .tokenization import Tokenizer, TokenMapping
from .crypto import (
    encrypt_mapping,
    decrypt_mapping,
    generate_key,
    CRYPTO_BACKEND,
    InvalidKeyError,
    CorruptedMappingError,
)
from .restoration import Restorer
from .report import build_report
from .pipeline import Pipeline, ProcessResult

__all__ = [
    "Detector",
    "Detection",
    "ColumnTreatment",
    "DETECTION_BACKEND",
    "Tokenizer",
    "TokenMapping",
    "encrypt_mapping",
    "decrypt_mapping",
    "generate_key",
    "CRYPTO_BACKEND",
    "InvalidKeyError",
    "CorruptedMappingError",
    "Restorer",
    "build_report",
    "Pipeline",
    "ProcessResult",
]

__version__ = "1.0.0"
