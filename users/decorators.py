"""
users/decorators.py – Role-Based Access Control (RBAC) decorators.

These decorators protect views by requiring specific roles.
They work alongside Django's @login_required decorator.

Usage:
    @login_required
    @role_required('ADMIN')
    def admin_only_view(request):
        ...

    @login_required
    @roles_required(['ADMIN', 'EMPLOYEE'])
    def admin_or_employee_view(request):
        ...
"""

from functools import wraps

from django.contrib import messages
from django.shortcuts import redirect


def role_required(role):
    """Decorator that restricts a view to a single role."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect("login")
            if request.user.role != role:
                messages.error(
                    request,
                    f"Access denied. This page requires {role.title()} privileges.",
                )
                return redirect("dashboard")
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def roles_required(roles):
    """Decorator that restricts a view to a list of allowed roles."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect("login")
            if request.user.role not in roles:
                allowed = ", ".join(r.title() for r in roles)
                messages.error(
                    request,
                    f"Access denied. This page requires one of: {allowed}.",
                )
                return redirect("dashboard")
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator
