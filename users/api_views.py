import json

from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import CustomUser, ExtensionToken


@csrf_exempt
@require_POST
def extension_login(request):
    try:
        body = json.loads(request.body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not email or not password:
        return JsonResponse({"error": "Email and password are required."}, status=400)

    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return JsonResponse({"error": "Invalid email or password."}, status=401)

    if user.is_account_locked:
        return JsonResponse({"error": "Account is temporarily locked."}, status=423)

    auth_user = authenticate(request, username=user.username, password=password)
    if auth_user is None:
        user.record_failed_login()
        return JsonResponse({"error": "Invalid email or password."}, status=401)

    auth_user.reset_failed_logins()
    _, raw_token = ExtensionToken.issue_for_user(auth_user)
    return JsonResponse({
        "token": raw_token,
        "user": {
            "email": auth_user.email,
            "username": auth_user.username,
            "role": auth_user.role,
        },
    })
