from django.urls import path
from . import views
from . import api_views
from . import extension_api
from . import gateway_api

urlpatterns = [
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("prompt/", views.prompt_view, name="prompt"),
    path("gateway-demo/", views.gateway_demo_view, name="gateway_demo"),
    path("logs/", views.logs_view, name="logs"),
    path("logs/<int:log_id>/delete/", views.delete_log_view, name="log_delete"),
    path("policy-rules/", views.policy_rules_view, name="policy_rules"),
    path("logs/<int:log_id>/", views.log_detail_view, name="log_detail"),
    path("logs/<int:log_id>/reveal/", views.ephemeral_sensitive_data, name="ephemeral_reveal"),

    # DLP and gateway JSON APIs.
    path("analyze", api_views.analyze, name="api_analyze"),
    path("analyze-file", api_views.analyze_file, name="api_analyze_file"),
    path("firewall/check", extension_api.firewall_check, name="extension_firewall_check"),
    path("firewall/check-response", extension_api.firewall_check_response, name="extension_firewall_check_response"),
    path("firewall/check-file", extension_api.firewall_check_file, name="extension_firewall_check_file"),
    path("gateway/chat", gateway_api.gateway_chat, name="gateway_chat"),
    path("gateway/files/scan", gateway_api.gateway_file_scan, name="gateway_file_scan"),
    path("gateway/providers", gateway_api.gateway_providers, name="gateway_providers"),
    path("gateway/v1/chat/completions", gateway_api.openai_compatible_chat, name="gateway_openai_compatible_chat"),
]
