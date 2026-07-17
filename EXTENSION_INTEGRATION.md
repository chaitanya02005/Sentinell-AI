# Chrome Extension Integration

The browser extension turns Sentinell.AI into a real LLM website firewall.

## Flow

```text
ChatGPT/Gemini prompt box
  -> content script intercepts send
  -> background worker calls Django /firewall/check
  -> backend authenticates extension token
  -> SecurityOrchestrator runs agents
  -> ALLOW / TOKENIZE / BLOCK
  -> extension submits, replaces, or blocks prompt
```

## Auth

The extension requires login with a Django account.

Endpoint:

```text
POST /extension/login/
```

Response:

```json
{
  "token": "...",
  "user": {
    "email": "user@example.com",
    "username": "user",
    "role": "EMPLOYEE"
  }
}
```

The token is stored in Chrome local storage and sent as:

```text
Authorization: Bearer <token>
```

## Firewall Check

Endpoint:

```text
POST /firewall/check
```

Request:

```json
{
  "text": "My email is person@example.com",
  "source": "chatgpt"
}
```

Response:

```json
{
  "action": "TOKENIZE",
  "processed_prompt": "My email is p***@***.com",
  "risk_score": 40,
  "risk_level": "MODERATE",
  "detected_types": ["email"],
  "reasons": ["Email is universally masked (applies to all roles)."]
}
```

## Evaluator Demo

1. Start backend.
2. Login to extension.
3. Open ChatGPT or Gemini.
4. Submit safe prompt: it passes.
5. Submit email prompt: extension replaces it with masked text.
6. Submit API key or `.env` prompt: extension blocks it.
