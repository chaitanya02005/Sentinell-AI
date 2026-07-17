"""
users/urls.py – URL configuration for authentication flows.
"""

from django.urls import path

from . import api_views, views

urlpatterns = [
    # Authentication
    path("login/", views.login_view, name="login"),
    path("oidc/login/", views.oidc_login_view, name="oidc_login"),
    path("oidc/callback/", views.oidc_callback_view, name="oidc_callback"),
    path("signup/", views.signup_view, name="signup"),
    path("logout/", views.logout_view, name="logout"),
    path("extension/login/", api_views.extension_login, name="extension_login"),
]
