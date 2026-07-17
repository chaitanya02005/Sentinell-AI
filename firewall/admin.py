from django.contrib import admin
from .models import PolicyRule, ResponseLog, TokenMap, PromptLog


@admin.register(TokenMap)
class TokenMapAdmin(admin.ModelAdmin):
    list_display = ("token_label", "user", "vault_provider", "vault_key_id", "vault_version", "created_at")
    list_filter = ("user", "vault_provider", "vault_purpose", "vault_version")
    readonly_fields = ("encrypted_value", "vault_provider", "vault_key_id", "vault_purpose", "vault_version", "created_at")


@admin.register(PromptLog)
class PromptLogAdmin(admin.ModelAdmin):
    list_display = ("user", "action", "risk_score", "risk_level", "detected_types_display", "timestamp")
    list_filter = ("action", "risk_level", "user")
    readonly_fields = ("original_prompt", "processed_prompt", "ai_response", "reasons", "agent_trace")


@admin.register(ResponseLog)
class ResponseLogAdmin(admin.ModelAdmin):
    list_display = ("user", "source", "action", "risk_score", "risk_level", "timestamp")
    list_filter = ("action", "risk_level", "source", "user")
    readonly_fields = ("original_response", "processed_response", "reasons", "agent_trace")


@admin.register(PolicyRule)
class PolicyRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "enabled", "priority", "action", "direction", "min_risk_score", "updated_at")
    list_filter = ("enabled", "action", "direction")
    search_fields = ("name", "description", "reason", "source_contains")
    readonly_fields = ("created_at", "updated_at")
    fieldsets = (
        ("Rule", {
            "fields": ("name", "description", "enabled", "priority", "action", "reason"),
        }),
        ("Scope", {
            "fields": ("direction", "roles", "excluded_roles", "source_contains"),
        }),
        ("Conditions", {
            "fields": ("detection_types", "keywords", "min_risk_score"),
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at"),
        }),
    )
