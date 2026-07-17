"""
firewall/risk_scorer.py
=======================
Context-Aware Risk Scoring Engine for Sentinell.AI.

Risk is calculated based on the COMBINATION of detected data types,
not just the individual type severity.

┌──────────────────────────────────────────────────────────────────────┐
│  CASE 1 — Only PII (email, phone, Aadhaar, etc.)                    │
│    Risk Score  : FIXED at 40%  (MODERATE)                            │
│    Action      : MASK (tokenize PII)                                 │
│    Rationale   : Personal info alone is sensitive but not dangerous.  │
│                  Masking protects the user without blocking the flow. │
├──────────────────────────────────────────────────────────────────────┤
│  CASE 2 — High-Risk Content ONLY (API keys, code, credentials…)      │
│    Risk Score  : 60–75%  (HIGH to SEVERE)                            │
│    Action      : BLOCK                                               │
│    Rationale   : Dangerous content without PII — block but lower     │
│                  severity than combined PII+credential exposure.      │
├──────────────────────────────────────────────────────────────────────┤
│  CASE 3 — PII + High-Risk Content together (CRITICAL)                │
│    Risk Score  : 80–95%  (CRITICAL)                                  │
│    Action      : BLOCK + MASK PII in preview                         │
│    Rationale   : Combined exposure of identity data with secrets     │
│                  is the most dangerous scenario — maximum risk.       │
├──────────────────────────────────────────────────────────────────────┤
│  CASE 4 — No sensitive data at all                                   │
│    Risk Score  : 0%  (LOW)                                           │
│    Action      : ALLOW                                               │
└──────────────────────────────────────────────────────────────────────┘

Risk Levels:
   0–20%  → LOW
  21–40%  → MODERATE
  41–60%  → HIGH
  61–80%  → SEVERE
  81–100% → CRITICAL

Threshold Enforcement:
  If risk_score >= 60 → flag should_block = True (used to escalate policy).
"""

from __future__ import annotations
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from .scanner import Detection

from .policy_engine import evaluate_policy, BLOCK

# ---------------------------------------------------------------------------
# PII types — personal information that gets MASKED, not blocked alone.
# When only these types are detected, risk is capped at 40% (MODERATE).
# ---------------------------------------------------------------------------
_PII_TYPES = frozenset({
    "email",
    "phone",
    "phone_words",
    "contextual_pii",
    "aadhaar",
    "mac_address",
    "ip_address",
    "passport",
})

# ---------------------------------------------------------------------------
# Severity weight for HIGH-RISK types (used to scale within ranges).
# Higher value = more severe. Used for CASE 2 (60-75) and CASE 3 (80-95).
# ---------------------------------------------------------------------------
_HIGH_RISK_SEVERITY: dict[str, int] = {
    # Technical content — lower severity high-risk
    "documentation":                20,
    "source_code":                  30,
    "sql_query":                    40,
    # Adversarial / social engineering — mid severity
    "adversarial_injection":        60,
    "credential_request":           60,
    "social_engineering_injection": 70,
    "encoded_payload":              70,
    # Credentials / financial — high severity
    "financial_account":            75,
    "api_key":                      80,
    "secret_token":                 80,
    "embedded_secret_key":          80,
    "debug_env_dump":               82,
    "password":                     85,
    "credit_card":                  90,
    "ssn":                          90,
    "cloud_key":                    95,
    # Cryptographic material — max severity
    "encryption_key":               100,
    "private_key":                  100,
}

_DEFAULT_SEVERITY = 50  # Fallback for unknown high-risk types
_RISK_THRESHOLD_BLOCK = 60  # Flag should_block when score >= 60%

# ---------------------------------------------------------------------------
# Risk level classification
# ---------------------------------------------------------------------------

_RISK_LEVELS = [
    (20,  "LOW"),
    (40,  "MODERATE"),
    (60,  "HIGH"),
    (80,  "SEVERE"),
    (100, "CRITICAL"),
]


def classify_risk(score: int) -> str:
    """Return risk level label for a given numeric score."""
    for threshold, label in _RISK_LEVELS:
        if score <= threshold:
            return label
    return "CRITICAL"


# ---------------------------------------------------------------------------
# Main risk calculation function — context-aware
# ---------------------------------------------------------------------------

def calculate_risk(
    role: str,
    detections: List["Detection"],
    direction: str = "PROMPT",
) -> dict:
    """
    Calculate the aggregate risk score using context-aware rules.

    The score depends on the COMBINATION of detected data types:

      CASE 1 — Only PII present       → Fixed 40% (MODERATE, don't block)
      CASE 2 — High-risk only (no PII) → 60–75%  (scale by severity)
      CASE 3 — PII + high-risk mix     → 80–95%  (scale by severity, CRITICAL)
      CASE 4 — No detections           → 0%      (LOW, allow)

    Args:
        role       : User role string — "ADMIN", "EMPLOYEE", or "INTERN".
        detections : List of Detection objects from scanner.scan().

    Returns:
        {
            "score":        int,   # 0–100
            "level":        str,   # LOW / MODERATE / HIGH / SEVERE / CRITICAL
            "should_block": bool,  # True if score >= 60
        }
    """
    if not detections:
        return {"score": 0, "level": "LOW", "should_block": False}

    # ── Classify all detected types into PII vs high-risk ─────────────────
    # A non-PII type is only "high-risk" if the policy engine actually
    # BLOCKS it for this role.  Types that are ALLOWED (e.g. sql_query
    # for ADMIN) don't escalate the risk score.
    pii_detected = set()
    high_risk_detected = set()

    for detection in detections:
        if detection.dtype in _PII_TYPES:
            pii_detected.add(detection.dtype)
        else:
            # Check what the policy engine says for this role
            action, _ = evaluate_policy(role, detection.dtype, direction=direction)
            if action == BLOCK:
                high_risk_detected.add(detection.dtype)

    has_pii = bool(pii_detected)
    has_high_risk = bool(high_risk_detected)

    # ── CASE 4: No sensitive data ─────────────────────────────────────────
    if not has_pii and not has_high_risk:
        return {"score": 0, "level": "LOW", "should_block": False}

    # ── CASE 1: Only PII (email, phone, Aadhaar, etc.) ────────────────────
    #    Fixed at 40% — personal info alone is masked, not blocked.
    if has_pii and not has_high_risk:
        score = 40
        level = classify_risk(score)
        return {
            "score":        score,
            "level":        level,
            "should_block": False,   # Never block PII-only prompts
        }

    # ── Find the max severity of the high-risk types ──────────────────────
    max_severity = 0
    for dtype in high_risk_detected:
        sev = _HIGH_RISK_SEVERITY.get(dtype, _DEFAULT_SEVERITY)

        # If this dtype is blocked by role policy, boost severity to at least 60
        action, _ = evaluate_policy(role, dtype, direction=direction)
        if action == BLOCK:
            sev = max(sev, 60)

        max_severity = max(max_severity, sev)

    # Normalise severity to 0.0–1.0 for range mapping
    severity_factor = min(max_severity, 100) / 100.0

    # ── CASE 3: PII + High-Risk Content (CRITICAL) ───────────────────────
    #    Range: 80–95%, scaled by high-risk severity.
    if has_pii and has_high_risk:
        score = 80 + round(severity_factor * 15)
        score = min(score, 95)
        level = classify_risk(score)
        return {
            "score":        score,
            "level":        level,
            "should_block": True,
        }

    # ── CASE 2: High-Risk Content Only (no PII) ──────────────────────────
    #    Range: 60–75%, scaled by high-risk severity.
    score = 60 + round(severity_factor * 15)
    score = min(score, 75)
    level = classify_risk(score)
    return {
        "score":        score,
        "level":        level,
        "should_block": True,
    }
