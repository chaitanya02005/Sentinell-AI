from django.db import connections
from django.http import JsonResponse
from django.views.decorators.http import require_GET


@require_GET
def healthz(request):
    checks = {"app": "ok", "database": "unknown"}
    status = 200

    try:
        with connections["default"].cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"
        status = 503

    return JsonResponse(
        {"status": "ok" if status == 200 else "error", "checks": checks},
        status=status,
    )
