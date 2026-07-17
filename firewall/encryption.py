"""
encryption.py – Fernet (AES-128 CBC) symmetric encryption helpers.

The Fernet key is read from Django settings (FERNET_KEY).
All encrypted values are stored as UTF-8 strings (base64 URL-safe).
"""

from cryptography.fernet import Fernet
from django.conf import settings


def _get_fernet() -> Fernet:
    key = settings.FERNET_KEY
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    """Encrypt a plain-text string and return a base64 encoded cipher string."""
    f = _get_fernet()
    token = f.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64 encoded cipher string and return the plain-text.

    NOTE: Not currently called by views.py (which only writes TokenMap rows).
    Preserved intentionally for a future secure de-tokenization endpoint
    (e.g. an admin-only API that retrieves the original masked PII value).
    Do NOT remove without checking for callers first.
    """
    f = _get_fernet()
    plaintext = f.decrypt(ciphertext.encode("utf-8"))
    return plaintext.decode("utf-8")
