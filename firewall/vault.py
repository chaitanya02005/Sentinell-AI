from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import json
import os
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .encryption import decrypt, encrypt


VAULT_FORMAT_VERSION = 1
MLKEM_VAULT_FORMAT_VERSION = 2
DEFAULT_PROVIDER = "local-fernet-envelope"
DEFAULT_KEY_ID = "fernet-local-v1"
MLKEM_PROVIDER = "ml-kem-1024-aesgcm-v1"
MLKEM_ALGORITHM = "ML-KEM-1024+HKDF-SHA256+AES-256-GCM"
_HKDF_INFO = b"Sentinell.AI Token Vault ML-KEM-1024 AES-GCM v1"


@dataclass(frozen=True)
class VaultSealedValue:
    ciphertext: str
    provider: str
    key_id: str
    purpose: str
    version: int = VAULT_FORMAT_VERSION

    def model_fields(self) -> dict[str, Any]:
        return {
            "encrypted_value": self.ciphertext,
            "vault_provider": self.provider,
            "vault_key_id": self.key_id,
            "vault_purpose": self.purpose,
            "vault_version": self.version,
        }


class VaultService:
    """
    Versioned vault boundary for sensitive value storage.

    The current provider is a local Fernet envelope so existing deployments stay
    decryptable. The interface is intentionally provider-neutral: a Kyber-1024
    or other NIST PQC KEM provider can later implement the same seal/open
    contract without changing TokenMap callers.
    """

    def __init__(self):
        self.provider = getattr(settings, "TOKEN_VAULT_PROVIDER", DEFAULT_PROVIDER)
        self.key_id = getattr(settings, "TOKEN_VAULT_KEY_ID", DEFAULT_KEY_ID)

    def seal(self, plaintext: str, *, purpose: str, context: dict[str, Any] | None = None) -> VaultSealedValue:
        if self.provider == MLKEM_PROVIDER:
            return self._seal_mlkem1024(plaintext, purpose=purpose, context=context)

        envelope = {
            "sentinell_vault": VAULT_FORMAT_VERSION,
            "provider": self.provider,
            "key_id": self.key_id,
            "purpose": purpose,
            "algorithm": "fernet-aes128-cbc-hmac-sha256",
            "pqc_ready": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "context": context or {},
            "ciphertext": encrypt(plaintext),
        }
        return VaultSealedValue(
            ciphertext=json.dumps(envelope, separators=(",", ":")),
            provider=self.provider,
            key_id=self.key_id,
            purpose=purpose,
        )

    def open(self, sealed_value: str) -> str:
        envelope = _parse_envelope(sealed_value)
        if envelope:
            if envelope.get("provider") == MLKEM_PROVIDER:
                return self._open_mlkem1024(envelope)
            return decrypt(str(envelope["ciphertext"]))
        return decrypt(sealed_value)

    def _seal_mlkem1024(
        self,
        plaintext: str,
        *,
        purpose: str,
        context: dict[str, Any] | None = None,
    ) -> VaultSealedValue:
        public_key = _load_mlkem1024_public_key()
        shared_secret, kem_ciphertext = public_key.encapsulate()
        salt = os.urandom(16)
        nonce = os.urandom(12)
        aes_key = _derive_aes_key(shared_secret, salt)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)

        envelope = {
            "sentinell_vault": MLKEM_VAULT_FORMAT_VERSION,
            "provider": MLKEM_PROVIDER,
            "key_id": self.key_id,
            "purpose": purpose,
            "algorithm": MLKEM_ALGORITHM,
            "pqc_ready": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "context": context or {},
            "kem_ciphertext": _b64e(kem_ciphertext),
            "salt": _b64e(salt),
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ciphertext),
        }
        return VaultSealedValue(
            ciphertext=json.dumps(envelope, separators=(",", ":")),
            provider=MLKEM_PROVIDER,
            key_id=self.key_id,
            purpose=purpose,
            version=MLKEM_VAULT_FORMAT_VERSION,
        )

    def _open_mlkem1024(self, envelope: dict[str, Any]) -> str:
        private_key = _load_mlkem1024_private_key()
        shared_secret = private_key.decapsulate(_b64d(str(envelope["kem_ciphertext"])))
        aes_key = _derive_aes_key(shared_secret, _b64d(str(envelope["salt"])))
        plaintext = AESGCM(aes_key).decrypt(
            _b64d(str(envelope["nonce"])),
            _b64d(str(envelope["ciphertext"])),
            None,
        )
        return plaintext.decode("utf-8")


def seal_value(plaintext: str, *, purpose: str, context: dict[str, Any] | None = None) -> VaultSealedValue:
    return VaultService().seal(plaintext, purpose=purpose, context=context)


def open_value(sealed_value: str) -> str:
    return VaultService().open(sealed_value)


def inspect_value(sealed_value: str) -> dict[str, Any]:
    envelope = _parse_envelope(sealed_value)
    if not envelope:
        return {
            "version": 0,
            "provider": "legacy-fernet",
            "key_id": "legacy",
            "purpose": "legacy",
            "algorithm": "fernet",
            "pqc_ready": False,
        }
    return {
        "version": envelope.get("sentinell_vault"),
        "provider": envelope.get("provider"),
        "key_id": envelope.get("key_id"),
        "purpose": envelope.get("purpose"),
        "algorithm": envelope.get("algorithm"),
        "pqc_ready": bool(envelope.get("pqc_ready")),
        "created_at": envelope.get("created_at"),
    }


def _parse_envelope(value: str) -> dict[str, Any] | None:
    if not isinstance(value, str) or not value.startswith("{"):
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict) or parsed.get("sentinell_vault") not in {VAULT_FORMAT_VERSION, MLKEM_VAULT_FORMAT_VERSION}:
        return None
    if "ciphertext" not in parsed:
        return None
    return parsed


def _load_mlkem1024_public_key():
    raw = getattr(settings, "MLKEM1024_PUBLIC_KEY", "")
    if not raw:
        raise ImproperlyConfigured("MLKEM1024_PUBLIC_KEY is required for the ML-KEM vault provider.")
    return mlkem.MLKEM1024PublicKey.from_public_bytes(_b64d(raw))


def _load_mlkem1024_private_key():
    raw = getattr(settings, "MLKEM1024_PRIVATE_KEY", "")
    if not raw:
        raise ImproperlyConfigured("MLKEM1024_PRIVATE_KEY is required to open ML-KEM vault values.")
    return mlkem.MLKEM1024PrivateKey.from_seed_bytes(_b64d(raw))


def _derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_HKDF_INFO,
    ).derive(shared_secret)


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))
