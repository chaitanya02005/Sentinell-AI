# Sentinell.AI Production Runbook

Sentinell.AI is an AI firewall backend. It inspects prompts before an LLM sees them, then blocks, tokenizes, or allows the sanitized prompt.

## Production Checklist

1. Copy `.env.example` to `.env`.
2. Fill real secrets:
   - `DJANGO_SECRET_KEY`
   - `DB_PASSWORD`
   - `FERNET_KEY`
   - `GROQ_API_KEY` or another provider key
3. Use a UTF-8 PostgreSQL database.
4. Set:
   - `DJANGO_ENV=production`
   - `DJANGO_DEBUG=False`
   - `DJANGO_ALLOWED_HOSTS=your-domain.com`
   - `CSRF_TRUSTED_ORIGINS=https://your-domain.com`
5. Keep `CORS_ALLOW_ALL_ORIGINS=False`.
6. Run migrations and collect static before serving traffic.

## Docker Compose

```powershell
docker compose up --build
```

Then check:

```text
http://127.0.0.1:8000/healthz/
```

Expected:

```json
{"status":"ok","checks":{"app":"ok","database":"ok"}}
```

## LLM Modes

Demo mode:

```env
LLM_PROVIDER=mock
```

Production Groq response mode:

```env
LLM_PROVIDER=groq
GROQ_API_KEY=...
GROQ_RESPONSE_MODEL=llama-3.3-70b-versatile
```

The response provider is called only after the firewall approves the prompt. PII tokenization happens before the provider receives the prompt.

## Semantic Security Agent

```env
SEMANTIC_AGENT_PROVIDER=groq
GROQ_SEMANTIC_MODEL=llama-3.3-70b-versatile
```

The local embedding classifier handles clear semantic decisions before any
external provider is called. Groq is used only for uncertain scores. If the
provider fails, the app preserves the local evidence and still enforces regex,
contextual PII, embedding, policy, and risk checks.

## Operational Notes

- Use HTTPS in production.
- Use a managed secret store when possible.
- Do not commit `.env`.
- Configure database backups.
- Monitor `/healthz/`.
- Review admin audit logs regularly.
