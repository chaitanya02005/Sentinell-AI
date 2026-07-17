from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from .health import healthz


def root_view(request):
    """Root entry point: redirect to dashboard if logged in, otherwise to login."""
    if request.user.is_authenticated:
        return redirect("dashboard")
    return redirect("login")


urlpatterns = [
    path("healthz/", healthz, name="healthz"),
    path("admin/", admin.site.urls),
    # Root → redirect based on auth status
    path("", root_view, name="root"),
    path("", include("firewall.urls")),
    path("", include("users.urls")),
]
