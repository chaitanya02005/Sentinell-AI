"""
firewall/detector.py
====================
Lightweight DLP decision function.

    detect_sensitive(text) → "SAFE" | "BLOCK"

Uses the existing regex scanner (scanner.py) — no heavy models required.
Easy to swap in BERT/RoBERTa later by replacing the body of detect_sensitive().

Sensitive categories that trigger BLOCK:
  • email, phone, phone_words
  • financial_account, credit_card, ssn, aadhaar
  • password, api_key, cloud_key, private_key, encryption_key, secret_token
  • adversarial_injection, encoded_payload, embedded_secret_key
  • social_engineering_injection, credential_request
  • source_code, sql_query
"""

import logging
from .scanner import scan

logger = logging.getLogger(__name__)

# Every dtype that should trigger a BLOCK decision.
_BLOCK_TYPES = frozenset({
    "email",
    "phone",
    "phone_words",
    "financial_account",
    "credit_card",
    "ssn",
    "aadhaar",
    "password",
    "api_key",
    "cloud_key",
    "private_key",
    "encryption_key",
    "secret_token",
    "adversarial_injection",
    "encoded_payload",
    "embedded_secret_key",
    "social_engineering_injection",
    "credential_request",
    "source_code",
    "sql_query",
    "mac_address",
    "ip_address",
    "passport",
})


def detect_sensitive(text: str) -> str:
    """
    Analyse *text* and return "BLOCK" if any sensitive data is detected,
    otherwise "SAFE".

    Logs each detected type for audit/debugging.
    """
    if not text or not text.strip():
        return "SAFE"

    detections = scan(text)
    triggered = {d.dtype for d in detections} & _BLOCK_TYPES

    if triggered:
        logger.warning("BLOCK — sensitive types detected: %s", ", ".join(sorted(triggered)))
        return "BLOCK"

    logger.info("SAFE — no sensitive data detected.")
    return "SAFE"
