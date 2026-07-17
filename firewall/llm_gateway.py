from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import urllib.error
import urllib.request

from django.conf import settings

from .mock_ai import ZERO_TRUST_SYSTEM_PROMPT, mock_ai

logger = logging.getLogger(__name__)


@dataclass
class GatewayLLMRequest:
    messages: list[dict]
    provider: str = ""
    model: str = ""
    temperature: float = 0.2
    max_tokens: int = 700
    metadata: dict = field(default_factory=dict)


@dataclass
class GatewayLLMResponse:
    provider: str
    model: str
    content: str
    raw: dict = field(default_factory=dict)
    fallback_used: bool = False


OPENAI_COMPATIBLE_PROVIDERS = {
    "groq": {
        "api_key_setting": "GROQ_API_KEY",
        "url_setting": "GROQ_CHAT_COMPLETIONS_URL",
        "default_url": "https://api.groq.com/openai/v1/chat/completions",
        "model_setting": "GROQ_RESPONSE_MODEL",
        "default_model": "llama-3.3-70b-versatile",
    },
    "openai": {
        "api_key_setting": "OPENAI_API_KEY",
        "url_setting": "OPENAI_CHAT_COMPLETIONS_URL",
        "default_url": "https://api.openai.com/v1/chat/completions",
        "model_setting": "OPENAI_RESPONSE_MODEL",
        "default_model": "gpt-4o-mini",
    },
    "xai": {
        "api_key_setting": "XAI_API_KEY",
        "url_setting": "XAI_CHAT_COMPLETIONS_URL",
        "default_url": "https://api.x.ai/v1/chat/completions",
        "model_setting": "XAI_RESPONSE_MODEL",
        "default_model": "grok-4.20-reasoning",
    },
    "openai_compatible": {
        "api_key_setting": "LLM_OPENAI_COMPATIBLE_API_KEY",
        "url_setting": "LLM_OPENAI_COMPATIBLE_URL",
        "default_url": "",
        "model_setting": "LLM_OPENAI_COMPATIBLE_MODEL",
        "default_model": "",
    },
}


def allowed_gateway_providers() -> list[str]:
    configured = getattr(settings, "LLM_ALLOWED_PROVIDERS", [])
    if configured:
        return [provider.strip().lower() for provider in configured if provider.strip()]
    return ["mock", "groq", "openai", "xai", "openai_compatible"]


def provider_available(provider: str) -> bool:
    provider = provider.lower()
    if provider == "mock":
        return True
    config = OPENAI_COMPATIBLE_PROVIDERS.get(provider)
    if not config:
        return False
    api_key = getattr(settings, config["api_key_setting"], "")
    url = getattr(settings, config["url_setting"], config["default_url"])
    return bool(api_key and url)


def gateway_provider_catalog() -> list[dict]:
    providers = []
    for provider in allowed_gateway_providers():
        providers.append({
            "id": provider,
            "available": provider_available(provider),
            "type": "local" if provider == "mock" else "openai_compatible",
            "default_model": default_model_for_provider(provider),
        })
    return providers


def default_model_for_provider(provider: str) -> str:
    provider = provider.lower()
    if provider == "mock":
        return "sentinell-mock-ai"
    config = OPENAI_COMPATIBLE_PROVIDERS.get(provider)
    if not config:
        return ""
    return getattr(settings, config["model_setting"], config["default_model"]) or config["default_model"]


def generate_ai_response(processed_prompt: str) -> str:
    """
    Backward-compatible helper for older callers.
    """
    response = generate_gateway_response(
        GatewayLLMRequest(
            provider=getattr(settings, "LLM_PROVIDER", "mock"),
            messages=[{"role": "user", "content": processed_prompt}],
        )
    )
    return response.content


def generate_gateway_response(request: GatewayLLMRequest) -> GatewayLLMResponse:
    provider = (request.provider or getattr(settings, "LLM_PROVIDER", "mock")).lower()
    if provider not in allowed_gateway_providers():
        logger.warning("LLM provider %s is not allowed; falling back to mock provider.", provider)
        return _mock_response(request, provider="mock", fallback_used=True)

    if provider == "mock":
        return _mock_response(request, provider="mock")

    if provider in OPENAI_COMPATIBLE_PROVIDERS:
        response = _call_openai_compatible(provider, request)
        if response:
            return response
        logger.warning("%s response provider unavailable; falling back to mock_ai.", provider)
        return _mock_response(request, provider=provider, fallback_used=True)

    logger.warning("Unknown LLM provider %s; falling back to mock provider.", provider)
    return _mock_response(request, provider="mock", fallback_used=True)


def _mock_response(request: GatewayLLMRequest, *, provider: str, fallback_used: bool = False) -> GatewayLLMResponse:
    prompt = _last_user_content(request.messages)
    return GatewayLLMResponse(
        provider=provider,
        model="sentinell-mock-ai",
        content=mock_ai(prompt),
        raw={"provider": "mock"},
        fallback_used=fallback_used,
    )


def _call_openai_compatible(provider: str, request_data: GatewayLLMRequest) -> GatewayLLMResponse | None:
    config = OPENAI_COMPATIBLE_PROVIDERS[provider]
    api_key = getattr(settings, config["api_key_setting"], "")
    url = getattr(settings, config["url_setting"], config["default_url"])
    if not api_key or not url:
        return None

    model = request_data.model or default_model_for_provider(provider)
    if not model:
        return None

    messages = [{"role": "system", "content": ZERO_TRUST_SYSTEM_PROMPT}]
    messages.extend(request_data.messages)
    payload = {
        "model": model,
        "messages": messages,
        "temperature": request_data.temperature,
    }
    if provider == "openai":
        payload["max_tokens"] = request_data.max_tokens
    else:
        payload["max_completion_tokens"] = request_data.max_tokens

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "SentinellAI/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=getattr(settings, "LLM_TIMEOUT", 20),
        ) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (TimeoutError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        logger.warning("%s response call failed: %s", provider, exc)
        return None

    choices = data.get("choices") or []
    if not choices:
        return None
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        return None

    return GatewayLLMResponse(
        provider=provider,
        model=model,
        content=content.strip(),
        raw={
            "id": data.get("id"),
            "usage": data.get("usage", {}),
            "finish_reason": choices[0].get("finish_reason"),
        },
    )


def _last_user_content(messages: list[dict]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user" and isinstance(message.get("content"), str):
            return message["content"]
    for message in reversed(messages):
        if isinstance(message.get("content"), str):
            return message["content"]
    return ""
