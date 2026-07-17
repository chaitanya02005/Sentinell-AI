"""
tokenization.py – Replace sensitive spans with industry-standard masks.

Masking strategy — dtype-specific, bank-grade security:

  PHONE        →  ******3210        (last 4 digits only, like banks/OTP screens)
  PHONE_WORDS  →  ******3210        (last 4 digits extracted from words)
  EMAIL        →  u***@***.com      (first char + *** + @ + *** + last domain part)
  AADHAAR      →  XXXX-XXXX-3456    (last 4 digits only, like UIDAI standard)
  CREDIT CARD  →  **** **** **** 1111  (last 4 digits, PCI-DSS standard)
  SSN          →  ***-**-6789       (last 4 digits, US standard)
  PASSPORT     →  ****567           (last 3 chars only)
  MAC ADDRESS  →  **:**:**:**:**:5E  (last octet only)
  IP ADDRESS   →  ***.***.***.100   (last octet only)
  API KEY      →  sk-***...***abc   (first 3 + *** + last 3)
  DEFAULT      →  ***...***         (first 2 + *** + last 2)

The original value is always stored encrypted in the database via TokenMap.
The mask is what gets shown in the UI and sent to the AI — never the real value.
"""

import re
from typing import List, Dict, Tuple
from .scanner import Detection


# ── Digit-word → digit mapping for phone_words ───────────────────────────────
_WORD_TO_DIGIT = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}


def _extract_digits(value: str) -> str:
    """Extract only digit characters from a string."""
    return re.sub(r"\D", "", value)


def _words_to_digits(value: str) -> str:
    """Convert spoken digit words to a digit string."""
    digits = []
    for word in re.split(r"[\s,]+", value.lower()):
        if word in _WORD_TO_DIGIT:
            digits.append(_WORD_TO_DIGIT[word])
    return "".join(digits)


# ── Dtype-specific masking functions ─────────────────────────────────────────

def _mask_phone(value: str) -> str:
    """
    Phone: show last 4 digits only — industry standard (banks, OTP screens).
    9876543210  →  ******3210
    +91 98765 43210  →  ******3210
    """
    digits = _extract_digits(value)
    if len(digits) >= 4:
        return "*" * (len(digits) - 4) + digits[-4:]
    return "*" * len(digits)


def _mask_phone_words(value: str) -> str:
    """
    Phone words: extract digits from spoken words, then apply phone masking.
    'nine eight seven six five four three two one zero'  →  ******3210
    """
    digits = _words_to_digits(value)
    if len(digits) >= 4:
        return "*" * (len(digits) - 4) + digits[-4:]
    return "*" * len(value)


def _mask_email(value: str) -> str:
    """
    Email: first char + *** + @ + *** + last domain part.
    john.doe@company.com          ->  j***@***.com
    admin@test.org                ->  a***@***.org
    admin (at) company (dot) com  ->  a***@***.com
    john[at]example[dot]org       ->  j***@***.org
    info AT company DOT net       ->  i***@***.net
    """
    # Normalise obfuscated forms to standard email first
    normalised = value
    normalised = re.sub(r'\s*\(at\)\s*', '@', normalised, flags=re.IGNORECASE)
    normalised = re.sub(r'\s*\[at\]\s*', '@', normalised, flags=re.IGNORECASE)
    normalised = re.sub(r'\s+at\s+',     '@', normalised, flags=re.IGNORECASE)
    normalised = re.sub(r'\s*\(dot\)\s*', '.', normalised, flags=re.IGNORECASE)
    normalised = re.sub(r'\s*\[dot\]\s*', '.', normalised, flags=re.IGNORECASE)
    normalised = re.sub(r'\s+dot\s+',     '.', normalised, flags=re.IGNORECASE)

    if "@" in normalised:
        local, _, domain = normalised.partition("@")
        # Mask local part: keep first char only
        masked_local = (local[0] if local else "*") + "***"
        # Mask domain: keep last extension only (e.g. .com, .org)
        dot_idx = domain.rfind(".")
        if dot_idx > 0:
            masked_domain = "***" + domain[dot_idx:]
        else:
            masked_domain = "***"
        return f"{masked_local}@{masked_domain}"
    # Fallback
    return (value[0] if value else "*") + "***"


def _mask_aadhaar(value: str) -> str:
    """
    Aadhaar: XXXX-XXXX-last4 — UIDAI standard.
    2345 6789 0123  →  XXXX-XXXX-0123
    """
    digits = _extract_digits(value)
    if len(digits) >= 4:
        return "XXXX-XXXX-" + digits[-4:]
    return "XXXX-XXXX-****"


def _mask_credit_card(value: str) -> str:
    """
    Credit card: **** **** **** last4 — PCI-DSS standard.
    4111 1111 1111 1111  →  **** **** **** 1111
    3714 496353 98431    →  **** ****** 8431  (Amex 15-digit)
    """
    digits = _extract_digits(value)
    if len(digits) >= 4:
        last4 = digits[-4:]
        # Determine card type by length for proper formatting
        if len(digits) == 15:
            # Amex: 4-6-5 format
            return "**** ****** " + last4 + "*"
        else:
            # Standard 16-digit: 4-4-4-4 format
            return "**** **** **** " + last4
    return "**** **** **** ****"


def _mask_ssn(value: str) -> str:
    """
    SSN: ***-**-last4 — US standard.
    123-45-6789  →  ***-**-6789
    """
    digits = _extract_digits(value)
    if len(digits) >= 4:
        return "***-**-" + digits[-4:]
    return "***-**-****"


def _mask_passport(value: str) -> str:
    """
    Passport: **** + last 3 chars.
    A1234567  →  *****567
    """
    if len(value) >= 3:
        return "*" * (len(value) - 3) + value[-3:]
    return "*" * len(value)


def _mask_mac_address(value: str) -> str:
    """
    MAC address: show last octet only.
    00:1A:2B:3C:4D:5E  →  **:**:**:**:**:5E
    """
    parts = re.split(r"[:\-]", value)
    if len(parts) == 6:
        return ":".join(["**"] * 5 + [parts[-1]])
    return "**:**:**:**:**:**"


def _mask_ip_address(value: str) -> str:
    """
    IP address: show last octet only.
    192.168.1.100  →  ***.***.***.100
    """
    parts = value.split(".")
    if len(parts) == 4:
        return ".".join(["***"] * 3 + [parts[-1]])
    return "***.***.***.***"


def _mask_default(value: str) -> str:
    """
    Default: first 2 + *** + last 2.
    Safer than first3+last3 — less information exposed.
    """
    n = len(value)
    if n <= 2:
        return "*" * n
    if n <= 5:
        return value[0] + "*" * (n - 1)
    return value[:2] + "*" * (n - 4) + value[-2:]


# ── Dtype → masking function dispatch ────────────────────────────────────────

_MASK_DISPATCH: Dict[str, callable] = {
    "phone":       _mask_phone,
    "phone_words": _mask_phone_words,
    "email":       _mask_email,
    "aadhaar":     _mask_aadhaar,
    "credit_card": _mask_credit_card,
    "ssn":         _mask_ssn,
    "passport":    _mask_passport,
    "mac_address": _mask_mac_address,
    "ip_address":  _mask_ip_address,
}


def _apply_mask(dtype: str, value: str) -> str:
    """Apply the correct masking function for the given dtype."""
    fn = _MASK_DISPATCH.get(dtype, _mask_default)
    return fn(value)


# ── Public tokenize function ──────────────────────────────────────────────────

def tokenize(prompt: str, targets: List[Detection]) -> Tuple[str, Dict[str, str]]:
    """
    Replace each detection in *targets* with a dtype-specific industry-standard mask.

    Masking is dtype-aware:
      - Phone      → last 4 digits (bank standard)
      - Email      → j***@***.com
      - Aadhaar    → XXXX-XXXX-1234
      - Credit card → **** **** **** 1234 (PCI-DSS)
      - SSN        → ***-**-6789
      - Others     → first2 + *** + last2

    The original value is stored in token_map for encrypted DB storage.
    The mask label is what appears in the processed prompt sent to AI.

    Returns:
        processed_prompt : str  – prompt with sensitive values masked
        token_map        : dict – {mask_label: original_value} for audit storage
    """
    if not targets:
        return prompt, {}

    # Deduplicate by (start, end) — keep first occurrence per span
    seen: set = set()
    unique_targets: List[Detection] = []
    for d in targets:
        key = (d.start, d.end)
        if key not in seen:
            seen.add(key)
            unique_targets.append(d)

    # Sort ascending by start position
    unique_targets.sort(key=lambda d: d.start)

    # Build replacement list with dtype-aware masks
    used_labels: Dict[str, int] = {}
    ordered: List[tuple] = []

    for detection in unique_targets:
        mask = _apply_mask(detection.dtype, detection.value)
        # Deduplicate mask labels if the same mask appears more than once
        if mask in used_labels:
            used_labels[mask] += 1
            label = f"{mask}[{used_labels[mask]}]"
        else:
            used_labels[mask] = 1
            label = mask
        ordered.append((detection.start, detection.end, label, detection.value))

    token_map: Dict[str, str] = {}
    result = prompt

    # Apply replacements right-to-left so earlier indices stay valid
    for start, end, label, original_value in reversed(ordered):
        token_map[label] = original_value
        result = result[:start] + label + result[end:]

    return result, token_map
