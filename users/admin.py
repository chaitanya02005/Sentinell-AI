from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = (
        "username",
        "email",
        "full_name",
        "role",
        "auth_provider",
        "department",
        "is_staff",
        "is_active",
        "failed_login_attempts",
    )
    list_filter = ("role", "auth_provider", "department", "is_staff", "is_active")
    search_fields = ("username", "email", "full_name", "external_subject", "tenant_id", "department")

    fieldsets = UserAdmin.fieldsets + (
        ("Role & Access", {"fields": ("role", "full_name")}),
        (
            "Enterprise Identity",
            {
                "fields": (
                    "auth_provider",
                    "external_subject",
                    "tenant_id",
                    "department",
                    "identity_claims",
                    "last_sso_login",
                )
            },
        ),
        (
            "Security",
            {
                "fields": (
                    "failed_login_attempts",
                    "account_locked_until",
                )
            },
        ),
    )

    add_fieldsets = UserAdmin.add_fieldsets + (
        ("Role & Access", {"fields": ("role", "full_name", "email")}),
    )
