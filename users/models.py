"""
users/models.py – Custom User model with RBAC and security fields.

Security Features:
  - Account lockout after failed login attempts
  - Role-based access control (Admin, Employee, Intern)
"""

from datetime import timedelta
import hashlib
import secrets

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class CustomUser(AbstractUser):
    """Extended user model with role-based access control and security features."""

    # ── Role Choices ──────────────────────────────────────────────────────────
    ADMIN = "ADMIN"
    EMPLOYEE = "EMPLOYEE"
    INTERN = "INTERN"

    ROLE_CHOICES = [
        (ADMIN, "Admin"),
        (EMPLOYEE, "Employee"),
        (INTERN, "Intern"),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=INTERN)

    # ── Account Lockout ───────────────────────────────────────────────────────
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(blank=True, null=True)

    # ── Full Name ─────────────────────────────────────────────────────────────
    full_name = models.CharField(max_length=150, blank=True, default="")

    # Enterprise identity metadata. Local demo users keep auth_provider="local".
    auth_provider = models.CharField(max_length=40, default="local")
    external_subject = models.CharField(max_length=255, blank=True, default="")
    tenant_id = models.CharField(max_length=120, blank=True, default="")
    department = models.CharField(max_length=120, blank=True, default="")
    identity_claims = models.JSONField(default=dict, blank=True)
    last_sso_login = models.DateTimeField(blank=True, null=True)

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        indexes = [
            models.Index(fields=["auth_provider", "external_subject"], name="users_sso_subject_idx"),
        ]

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

    # ── Role helpers ──────────────────────────────────────────────────────────
    def is_admin_role(self):
        return self.role == self.ADMIN

    def is_employee_role(self):
        return self.role == self.EMPLOYEE

    def is_intern_role(self):
        return self.role == self.INTERN

    @property
    def identity_context(self):
        """Zero Trust context used by policy and audit layers."""
        return {
            "auth_provider": self.auth_provider,
            "external_subject": self.external_subject,
            "tenant_id": self.tenant_id,
            "department": self.department,
            "role": self.role,
        }

    # ── Account Lockout helpers ───────────────────────────────────────────────
    @property
    def is_account_locked(self):
        """Check if the account is currently locked."""
        if self.account_locked_until and timezone.now() < self.account_locked_until:
            return True
        return False

    def record_failed_login(self):
        """Record a failed login attempt. Lock after 5 failures for 30 minutes."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.account_locked_until = timezone.now() + timedelta(minutes=30)
        self.save(update_fields=["failed_login_attempts", "account_locked_until"])

    def reset_failed_logins(self):
        """Reset failed login counter after successful login."""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save(update_fields=["failed_login_attempts", "account_locked_until"])


class ExtensionToken(models.Model):
    """Bearer token for browser extension API access."""

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="extension_tokens")
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(blank=True, null=True)
    revoked_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        status = "revoked" if self.revoked_at else "active"
        return f"ExtensionToken({self.user.username}, {status})"

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @classmethod
    def issue_for_user(cls, user: CustomUser) -> tuple["ExtensionToken", str]:
        raw_token = secrets.token_urlsafe(32)
        instance = cls.objects.create(user=user, token_hash=cls.hash_token(raw_token))
        return instance, raw_token

    @classmethod
    def authenticate(cls, raw_token: str) -> CustomUser | None:
        if not raw_token:
            return None
        try:
            token = cls.objects.select_related("user").get(
                token_hash=cls.hash_token(raw_token),
                revoked_at__isnull=True,
            )
        except cls.DoesNotExist:
            return None
        token.last_used_at = timezone.now()
        token.save(update_fields=["last_used_at"])
        return token.user
