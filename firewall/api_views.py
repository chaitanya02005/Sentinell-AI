"""
firewall/api_views.py
=====================
JSON API endpoints for the DLP safety checker.

  POST /analyze        — accepts { "text": "..." }
  POST /analyze-file   — accepts multipart file upload (PDF, DOCX, TXT, image)

Both endpoints return:
  { "status": "SAFE" }   or   { "status": "BLOCK" }

Pipeline (identical for both):
  Input (text | file) → extract text → detect_sensitive() → JSON response
"""

import json
import logging

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .detector import detect_sensitive
from .document_extractor import extract_text

logger = logging.getLogger(__name__)


@csrf_exempt
@require_POST
def analyze(request):
    """
    POST /analyze
    Body: application/json  →  { "text": "<content>" }
    """
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    text = body.get("text", "")
    if not isinstance(text, str) or not text.strip():
        return JsonResponse({"error": "Field 'text' is required and must be a non-empty string."}, status=400)

    status = detect_sensitive(text)
    logger.info("POST /analyze → %s (length=%d)", status, len(text))
    return JsonResponse({"status": status})


@csrf_exempt
@require_POST
def analyze_file(request):
    """
    POST /analyze-file
    Body: multipart/form-data  →  file field named 'document'
    Supported: PDF, DOCX, TXT, PNG, JPG, JPEG, BMP, TIFF, WEBP
    """
    # ── RBAC: Intern document upload restriction ────────────────────────
    # Interns cannot upload/analyze documents, enforced at API level.
    if hasattr(request, 'user') and request.user.is_authenticated:
        if getattr(request.user, 'role', '') == 'INTERN':
            return JsonResponse(
                {"error": "Access Denied: Interns cannot upload or access document files."},
                status=403
            )

    uploaded = request.FILES.get("document")
    if not uploaded:
        return JsonResponse({"error": "No file uploaded. Use field name 'document'."}, status=400)

    text, error = extract_text(uploaded)
    if error:
        return JsonResponse({"error": error}, status=422)

    status = detect_sensitive(text)
    logger.info("POST /analyze-file [%s] → %s (length=%d)", uploaded.name, status, len(text))
    return JsonResponse({"status": status})
