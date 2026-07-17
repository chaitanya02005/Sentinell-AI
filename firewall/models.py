import json
import logging
from django.db import models
from django.conf import settings

from .encryption import decrypt
from .vault import open_value


class TokenMap(models.Model):
    """Maps a token label to its encrypted original sensitive value."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token_label = models.CharField(max_length=30)        # e.g. [EMAIL_TOKEN], [API_KEY_TOKEN]
    encrypted_value = models.TextField()                  # Vault envelope or legacy Fernet value
    vault_provider = models.CharField(max_length=80, default="legacy-fernet")
    vault_key_id = models.CharField(max_length=120, blank=True, default="")
    vault_purpose = models.CharField(max_length=80, default="pii_token_map")
    vault_version = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.token_label} ({self.user.username})"

    @property
    def decrypted_value(self):
        try:
            return open_value(self.encrypted_value)
        except Exception:
            logger = logging.getLogger(__name__)
            logger.warning(
                "Could not open vault value for TokenMap id=%s; returning masked placeholder.",
                self.pk,
            )
            return "[UNAVAILABLE]"


class PromptLog(models.Model):
    """Audit log for every prompt submitted through the firewall."""

    ACTION_CHOICES = [
        ("ALLOW", "Allow"),
        ("BLOCK", "Block"),
        ("TOKENIZE", "Tokenize"),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    original_prompt = models.TextField()
    processed_prompt = models.TextField(blank=True)
    detected_types = models.JSONField(default=list)       # list of dtype strings
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    reasons = models.JSONField(default=list)
    risk_score = models.IntegerField(default=0)           # 0–100
    risk_level = models.CharField(max_length=10, default="LOW")  # LOW/MODERATE/HIGH/SEVERE/CRITICAL
    agent_trace = models.JSONField(default=dict)
    ai_response = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"[{self.action}] {self.user} @ {self.timestamp:%Y-%m-%d %H:%M}"

    def detected_types_display(self):
        return ", ".join(self.detected_types) if self.detected_types else "None"

    @property
    def plain_english_summary(self):
        """Return a concise explanation suitable for the audit activity list."""
        subject = self.user.email if self.user else "an unknown user"
        detected = ", ".join(
            str(item).replace("_", " ") for item in self.detected_types[:3]
        )
        if self.action == "BLOCK":
            detail = f" because it contained {detected}" if detected else ""
            return f"Blocked a high-risk prompt from {subject}{detail}. No protected data was sent to the AI."
        if self.action == "TOKENIZE":
            detail = f" including {detected}" if detected else ""
            return f"Masked sensitive information from {subject}{detail}, then allowed the protected prompt."
        return f"Allowed a prompt from {subject} after it passed the organization security policy."

    @property
    def decrypted_original_prompt(self):
        """Decrypt the stored original_prompt on-the-fly for display.

        Falls back to the raw stored value if decryption fails
        (e.g. legacy rows that were saved before encryption was enabled).
        """
        try:
            return decrypt(self.original_prompt)
        except Exception:
            logger = logging.getLogger(__name__)
            logger.warning(
                "Could not decrypt original_prompt for PromptLog id=%s; "
                "returning raw value (may be a legacy unencrypted row).",
                self.pk,
            )
            return self.original_prompt


class ResponseLog(models.Model):
    """Audit log for AI responses inspected before display or reuse."""

    ACTION_CHOICES = [
        ("ALLOW", "Allow"),
        ("REDACT", "Redact"),
        ("BLOCK", "Block"),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    source = models.CharField(max_length=80, default="browser_extension")
    original_response = models.TextField()
    processed_response = models.TextField(blank=True)
    detected_types = models.JSONField(default=list)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    reasons = models.JSONField(default=list)
    risk_score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=10, default="LOW")
    agent_trace = models.JSONField(default=dict)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"[RESPONSE {self.action}] {self.user} @ {self.timestamp:%Y-%m-%d %H:%M}"

    @property
    def decrypted_original_response(self):
        try:
            return decrypt(self.original_response)
        except Exception:
            logger = logging.getLogger(__name__)
            logger.warning(
                "Could not decrypt original_response for ResponseLog id=%s; "
                "returning raw value (may be a legacy unencrypted row).",
                self.pk,
            )
            return self.original_response


class PolicyRule(models.Model):
    """Admin-managed additive rules layered on top of the built-in Zero Trust policy."""

    ALLOW = "ALLOW"
    TOKENIZE = "TOKENIZE"
    BLOCK = "BLOCK"

    ACTION_CHOICES = [
        (ALLOW, "Allow"),
        (TOKENIZE, "Tokenize"),
        (BLOCK, "Block"),
    ]

    PROMPT = "PROMPT"
    RESPONSE = "RESPONSE"
    BOTH = "BOTH"

    DIRECTION_CHOICES = [
        (PROMPT, "Prompt"),
        (RESPONSE, "Response"),
        (BOTH, "Prompt and response"),
    ]

    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    priority = models.PositiveIntegerField(default=100)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES, default=BLOCK)
    direction = models.CharField(max_length=10, choices=DIRECTION_CHOICES, default=BOTH)
    roles = models.JSONField(default=list, blank=True)
    excluded_roles = models.JSONField(default=list, blank=True)
    detection_types = models.JSONField(default=list, blank=True)
    keywords = models.JSONField(default=list, blank=True)
    source_contains = models.CharField(max_length=120, blank=True)
    min_risk_score = models.PositiveIntegerField(default=0)
    reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["priority", "name"]

    def __str__(self):
        status = "enabled" if self.enabled else "disabled"
        return f"{self.name} ({self.action}, {status})"
