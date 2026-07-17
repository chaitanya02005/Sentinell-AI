"""
users/middleware.py – Security middleware for rate limiting and request sanitization.

Security Features:
  - Rate limiting: Limits login attempts to prevent brute-force attacks
  - Request sanitization: Adds security headers to responses
  - Login attempt tracking is done at the model level (see CustomUser.record_failed_login)
"""

import time
from collections import defaultdict

from django.http import JsonResponse
from django.shortcuts import render


class RateLimitMiddleware:
    """
    Rate-limit middleware for login and auth endpoints.

    Tracks IP-based request rates and returns HTTP 429 when exceeded.
    Default: 10 requests per minute for auth endpoints.
    """

    # In-memory store (use Redis in production for multi-process deployments)
    _rate_limits = defaultdict(list)

    # Configuration
    RATE_LIMIT = 10  # max requests
    RATE_WINDOW = 60  # seconds
    AUTH_PATHS = ["/login/", "/signup/"]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only rate-limit auth endpoints
        if request.path in self.AUTH_PATHS and request.method == "POST":
            client_ip = self._get_client_ip(request)
            now = time.time()

            # Clean old entries
            self._rate_limits[client_ip] = [
                t for t in self._rate_limits[client_ip]
                if now - t < self.RATE_WINDOW
            ]

            if len(self._rate_limits[client_ip]) >= self.RATE_LIMIT:
                return render(request, "users/rate_limited.html", status=429)

            self._rate_limits[client_ip].append(now)

        response = self.get_response(request)

        # Add security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response

    @staticmethod
    def _get_client_ip(request):
        """Extract client IP, respecting X-Forwarded-For header."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")
