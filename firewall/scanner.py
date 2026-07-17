"""
firewall/scanner.py
===================
Regex-based sensitive data detector for Sentinell.AI.

Detects the following data types (aligned with Zero Trust policy engine):

  FINANCIAL / CREDENTIAL:
    credit_card            – 16-digit card numbers
    password               – Password assignments in any format (including contextual)
    encryption_key         – PEM-encoded private keys
    private_key            – Generic private key markers
    ssn                    – US Social Security Numbers
    aadhaar                – Indian Aadhaar numbers (12-digit)
    financial_account      – Bank account / IBAN / routing numbers

  IDENTITY / CONTACT:
    email                  – Email addresses (standard + obfuscated forms)
    phone                  – Indian mobile numbers (numeric)
    phone_words            – Phone numbers spoken in digit words (e.g. "nine eight seven...")

  TECHNICAL:
    api_key                – API keys (all major formats: prefixed, UUID, JWT, AKIA, dot-sep, hex, base64)
    source_code            – Python / JS / PHP / SQL-shell code patterns
    sql_query              – SQL DML/DDL statements
    documentation          – Internal doc markers (approximated)

  SOCIAL ENGINEERING / CREDENTIAL HARVESTING:
    credential_request     – Requests asking to list/get/share credentials, passwords, or bank details

  ADVERSARIAL / ATTACK VECTORS (UNIVERSAL BLOCK):
    adversarial_injection        – Jailbreak / role-override / instruction-manipulation phrases
    encoded_payload              – Base64 or hex-encoded instruction blobs
    secret_token                 – Secret tokens and authentication credentials
    embedded_secret_key          – Short secrets hidden in prompts (e.g. "secret key: rpUnff", "key: abc123")
    social_engineering_injection – PWNED-style attacks: phrase redefinition + forced output + 'ignore rules'
"""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class Detection:
    dtype: str      # Data type label (e.g. "email", "api_key")
    value: str      # Raw matched text
    start: int      # Start index in prompt string
    end: int        # End index in prompt string


# ---------------------------------------------------------------------------
# Spoken digit words helper
# ---------------------------------------------------------------------------

# All word forms of digits (supports zero through nine only — phone numbers)
_DIGIT_WORDS = (
    r"zero|one|two|three|four|five|six|seven|eight|nine"
)

# Spoken phone number: 8–12 digit-words (covers Indian 10-digit, international)
# Allows spaces or commas between words. Case-insensitive.
_PHONE_WORDS_PATTERN = re.compile(
    r"(?i)\b(?:(?:"
    + _DIGIT_WORDS
    + r")(?:\s+|,\s*)){"
    r"7,11}"                  # 7 more after the first → 8–12 total
    r"(?:"
    + _DIGIT_WORDS
    + r")\b",
)

# Context-aware phone fallback:
# A short/odd digit sequence can still be PII when the user explicitly labels
# it as their phone/contact/WhatsApp number. This catches prompts like
# "my phone number is 888588858" without treating every random 9-digit ID as PII.
_CONTEXTUAL_PHONE_PATTERN = re.compile(
    r"""
    \b(?:
        (?:my|mine|personal|contact)\s+
            (?:phone|mobile|cell|contact|whats\s*app|whatsapp|number)
      | (?:phone|mobile|cell|contact|whats\s*app|whatsapp)
            \s*(?:number|no\.?|\#)?
      | (?:call|text|sms|reach|contact)\s+me\s+(?:at|on)
    )
    \s*(?:number|no\.?|\#)?\s*(?:is|=|:|-)?
    \s*(?P<number>\+?\d(?:[\s\-().]*\d){6,14})
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Generic contextual PII fallback:
# Unknown identifiers cannot be enumerated completely. Instead, detect values
# when surrounding words explicitly label them as sensitive identity, account,
# medical, address, or company-user data.
_CONTEXTUAL_PII_PATTERN = re.compile(
    r"""
    \b(?:
        (?:my|mine|personal|private|confidential)?\s*
        (?:
            employee|staff|user|customer|client|patient|student|member|vendor|
            account|case|ticket|policy|insurance|claim|subscription|profile|
            national|tax|license|licence|device|serial|asset|card|crm|hr|
            address|dob|birth\s*date|date\s*of\s*birth
        )
        \b
        \s*(?:id|no\.?|\#|number|code|ref(?:erence)?|identifier|token|address|dob)?
    )
    \s*(?:is|=|:|-)?
    \s*(?P<value>
        (?:[A-Z0-9][A-Z0-9._/\-]{2,63}[A-Z0-9])
        |
        (?:\d{1,4}[/-]\d{1,2}[/-]\d{2,4})
        |
        (?:[A-Za-z0-9][A-Za-z0-9\s,./#-]{5,80})
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _looks_like_contextual_pii_value(value: str) -> bool:
    cleaned = value.strip(" .,:;")
    if len(cleaned) < 4 or len(cleaned) > 96:
        return False
    if re.search(r"\d", cleaned):
        return True
    if re.search(r"[-_/#]", cleaned):
        return True
    return len(cleaned.split()) >= 2


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

PATTERNS: dict[str, re.Pattern] = {

    # ── Financial ──────────────────────────────────────────────────────────
    "credit_card": re.compile(
        # Visa (16-digit, starts 4)
        r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
        r"|"
        # Mastercard (16-digit, starts 51-55)
        r"\b5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
        r"|"
        # Amex (15-digit, starts 34 or 37) — format: 4-6-5
        r"\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b"
        r"|"
        # Discover (16-digit, starts 6011)
        r"\b6011[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
    ),
    "financial_account": re.compile(
        # IBAN (international)
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,18}\b"
        r"|"
        # Indian account number patterns (9-18 digits)
        r"\b(?:account\s*(?:no|number|#)?[\s:]*)\d{9,18}\b"
        r"|"
        # IFSC code (Indian Financial System Code): 4 letters + 0 + 6 alphanumeric
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        re.IGNORECASE,
    ),

    # ── Credentials ───────────────────────────────────────────────────────
    "password": re.compile(
        # Assignment forms: password=xxx, pass: xxx, etc.
        r"(?:password|passwd|pass|pwd|secret)\s*[=:]\s*\S{4,}"
        r"|"
        # Contextual: "the password is ...", "password is hidden in ... : <val>"
        # Also catches "database password is: value"
        r"(?:password|passwd|pwd)\s+is\s*[=:]?\s*(?:hidden\s+in\s+\S+\s*:\s*)?\S{4,}"
        r"|"
        # Standalone credential phrase: "password <value>" with a likely credential value
        r"\b(?:password|passwd)\s+(?:for|to)?\s*\S{6,}",
        re.IGNORECASE,
    ),
    "encryption_key": re.compile(
        # Private key PEM headers (all standard types)
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"
        r"|"
        # Public key PEM headers — asymmetric public keys (format #10)
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PUBLIC\s+KEY-----",
        re.IGNORECASE,
    ),
    "private_key": re.compile(
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?(?:PRIVATE|ENCRYPTED)\s+KEY-----"
        r"|"
        r"\b(?:private_?key|secret_?key)\s*[=:]\s*\S{8,}",
        re.IGNORECASE,
    ),

    # ── National IDs ──────────────────────────────────────────────────────
    "ssn": re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"           # 123-45-6789
    ),
    "aadhaar": re.compile(
        r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b"  # 12-digit, starts 2-9
    ),

    # ── Identity / Contact ────────────────────────────────────────────────
    "email": re.compile(
        # Standard email
        r"\b[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+\b"
        r"|"
        # Obfuscated: admin (at) company (dot) com / admin[at]company[dot]com
        r"\b[a-zA-Z0-9_.+\-]+\s*(?:\(at\)|\[at\]|at)\s*[a-zA-Z0-9\-]+\s*(?:\(dot\)|\[dot\]|dot)\s*[a-zA-Z]{2,}\b",
        re.IGNORECASE,
    ),
    "phone": re.compile(
        # ── Core: 10-digit Indian mobile (starts 6-9), optional +91/0091/91 prefix ──
        # Handles: 9876543210 | +91 9876543210 | +91-9876543210 | 0091-9076543210
        # Negative lookbehind for # and non-Indian ISD codes
        # Use negative lookahead on preceding word to exclude invoice/order numbers
        r"(?<!\d)(?<!#)(?<!\+1\s)(?<!\+[2-9]\s)"
        r"(?:\+91|0091|91)?[\s\-]?[6-9]\d{9}(?!\d)"
        r"|"
        # ── +91 with various separators before 10-digit number ──────────────
        # Handles: +91 98765 43210 | +91-98765-43210 | +91.9876.543.210
        # Also: +91 80 12345678 (city code format) | +91 (987) 654-3210
        r"\+91[\s\-.]?\(?\d{2,5}\)?[\s\-.]?\d{3,6}[\s\-.]?\d{0,6}"
        r"|"
        # ── Spaced/separated 10-digit (no prefix) — all common separators ──
        # Must start with 6-9 to be Indian mobile
        # Exclude UK-style: +44 7911 123456 by requiring word boundary before digit
        r"(?<!\+\d{2}\s)\b[6-9]\d{4}[\s\-\.]\d{5}\b"     # 5+5: 98765 43210
        r"|"
        r"(?<!\+\d{2}\s)\b[6-9]\d{3}[\s\-\.]\d{6}\b"     # 4+6: 9876 543210
        r"|"
        r"\b[6-9]\d{2}[\s\-\.]\d{3}[\s\-\.]\d{4}\b"       # 3+3+4: 987-654-3210
        r"|"
        r"\b[6-9]\d{3}[\s\-\.]\d{3}[\s\-\.]\d{3}\b"       # 4+3+3: 9876-543-210
        r"|"
        r"\b[6-9]\d{3}[\s\-\.]\d{4}[\s\-\.]\d{2}\b"       # 4+4+2: 9876 5432 10
        r"|"
        r"\b[6-9]\d{1}[\s\-\.]\d{2}[\s\-\.]\d{2}[\s\-\.]\d{2}[\s\-\.]\d{2}\b"  # 2+2+2+2+2
        r"|"
        # ── Single space between every digit (9 8 7 6 5 4 3 2 1 0) ─────────
        r"\b[6-9](?:\s\d){9}\b"
        r"|"
        # ── Parenthesis format: (98765) 43210 ───────────────────────────────
        r"\([6-9]\d{4}\)\s?\d{5}\b"
        r"|"
        # ── 0091 ISD prefix ──────────────────────────────────────────────────
        r"\b0091[\s\-]?[6-9]\d{9}\b"
        r"|"
        # ── Toll-free / landline starting with 1800/1860/1900 ───────────────
        r"\b1(?:800|860|900)\d{6,7}\b"
    ),
    "mac_address": re.compile(
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b"
    ),
    "ip_address": re.compile(
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        r"|"
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ),
    "passport": re.compile(
        r"\b[A-Z]{1,2}[0-9]{7,8}\b"
    ),

    # ── Phone numbers spoken as words ─────────────────────────────────────
    "phone_words": _PHONE_WORDS_PATTERN,

    # ── API Keys (Basic Risk — MASK) ─────────────────────────────────────
    # Covers: simple random, prefixed SaaS, JWT, OAuth, UUID, Base64, HMAC, GitHub tokens
    # Cloud keys (AKIA/cloud secrets) are in `cloud_key` dtype below (HIGH RISK).
    "api_key": re.compile(
        # ── Simple Random Alphanumeric (32-64 chars) — context-aware ──
        r"(?:(?:key|token|secret|api|auth|credential|access)\s*[=:\s]\s*)[A-Za-z0-9]{32,64}\b"
        r"|"
        # Context-labeled keys often use separators: example-api-key-abc123...
        r"(?:(?:key|token|secret|api|auth|credential|access)\s*[=:\s]\s*)[A-Za-z0-9][A-Za-z0-9_\-]{15,}\b"
        r"|"
        # Natural-language key context: "my key is example-api-key-..."
        r"\b(?:key|token|secret|api|auth|credential|access)\b\s+(?:is|as)\s+[A-Za-z0-9][A-Za-z0-9_\-]{15,}\b"
        r"|"
        # Standalone 40-64 char alphanumeric (length = high suspicion)
        r"\b[A-Za-z0-9]{40,64}\b"
        r"|"
        # ── Prefixed SaaS Key (sk_prod_xxx, pk_live_xxx, sk-xxx) ──
        r"\b(?:sk|pk|rk|ak)\-[A-Za-z0-9]{8,}\b"
        r"|"
        r"\b(?:sk|pk|rk|ak)_(?:live|test|prod|dev|staging|secret|private|v\d+)(?:_[A-Za-z0-9_]{4,})?\b"
        r"|"
        r"\b(?:sk|pk|rk|ak)_[a-z]+_v\d+_[A-Za-z0-9]{8,}\b"
        r"|"
        # ── Short hex key in context (16-29 chars) ──
        r"(?:(?:key|token|secret|api|auth)\s*[=:]\s*)[0-9a-fA-F]{16,29}\b"
        r"|"
        # ── UUID token (8-4-4-4-12) ──
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        r"|"
        # ── Base64-padded secret (ends with = or ==) ──
        r"\b[A-Za-z0-9+/]{20,}={1,2}\b"
        r"|"
        # ── JWT (three base64url segments) ──
        r"\b[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b"
        r"|"
        # ── HMAC Credential Pair (client_id:hexsecret) ──
        r"\b[a-zA-Z][a-zA-Z0-9_\-]{4,40}:[0-9a-fA-F]{20,}\b"
        r"|"
        # ── OAuth Token (ya29. prefix) ──
        r"\bya29\.[A-Za-z0-9\-_.]{20,}\b"
        r"|"
        # ── Metadata-embedded key (env_region_service_randomchars) ──
        r"\b[a-z]{2,12}_[a-z]{2,12}(?:_[a-z0-9]{2,20}){0,3}_[A-Za-z0-9]{16,}\b"
        r"|"
        # ── Named key/token assignments ──
        r"(?:api[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{16,}['\"]?"
        r"|"
        # ── Dot-separated tokens: id.rand.sig ──
        r"\b[A-Za-z0-9]{6,}\.[A-Za-z0-9]{6,}\.[A-Za-z0-9]{6,}\b"
        r"|"
        # ── GitHub / GitLab / npm prefixed tokens ──
        r"\b(?:ghp|gho|ghu|ghs|ghr|glpat|npm_)[_A-Za-z0-9]{20,}\b"
        r"|"
        # ── Bearer / Token header ──
        r"(?:Bearer|Token)\s+[A-Za-z0-9\-_.+/]{20,}",
        re.IGNORECASE,
    ),

    # ── Cloud Keys (HIGH / CRITICAL RISK — BLOCK) ─────────────────────────
    # Covers: AWS AKIA access keys, cloud secrets with forward slashes (AWS-style)
    "cloud_key": re.compile(
        # AWS Cloud Access Key IDs (AKIA/ASIA/AROA/AIDA/ANPA/ANVA/APKA + 12-20 chars)
        # Extended upper bound to 20 to catch longer variants like AKIAIOSFODNN7EXAMPLEKEY
        r"\b(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{12,20}\b"
        r"|"
        # AWS-style Cloud Secret Key (Base64-like with multiple forward slashes)
        # e.g. wJalrXUtnFEMI/K7MDENG/bPxRfiCYTESTKEY123
        r"[A-Za-z0-9+/]{8,}(?:/[A-Za-z0-9+]{4,}){2,}[A-Za-z0-9+/]*",
        re.IGNORECASE,
    ),

    # ── Source Code ───────────────────────────────────────────────────────
    "source_code": re.compile(
        r"(?im)(?:"
        # Python: def/class/import at line start OR inline (after any text)
        r"(?:^|\s)def\s+\w+\s*\("
        r"|(?:^|\s)class\s+\w+[\s:(]"
        r"|(?:^|\b)import\s+[\w.]+"
        r"|(?:^|\b)from\s+[\w.]+\s+import"
        # JS/TS
        r"|(?:^|\s)function\s+\w+\s*\("
        r"|(?:^|\s)const\s+\w+\s*="
        r"|(?:^|\s)let\s+\w+\s*="
        r"|(?:^|\s)var\s+\w+\s*="
        # PHP / C
        r"|<\?php"
        r"|#include\s*<"
        # Code context keywords
        r"|(?:source\s+code|my\s+code|the\s+code|this\s+(?:script|program|function|snippet))"
        r")"
    ),

    # ── SQL Queries ───────────────────────────────────────────────────────
    "sql_query": re.compile(
        # SELECT must be followed by * or column/aggregate list then FROM
        r"\bSELECT\s+(?:\*|[\w\(\)\*,\s]+?)\s+FROM\b"
        r"|"
        # INSERT must use INTO keyword (INSERT INTO table)
        r"\bINSERT\s+INTO\s+\w+"
        r"|"
        # UPDATE must have SET keyword
        r"\bUPDATE\s+\w+\s+SET\b"
        r"|"
        # DELETE must have FROM keyword
        r"\bDELETE\s+FROM\s+\w+"
        r"|"
        # DROP/CREATE/ALTER/TRUNCATE must be followed by TABLE/DATABASE/INDEX
        r"\bDROP\s+(?:TABLE|DATABASE|INDEX)\b"
        r"|"
        r"\bCREATE\s+(?:TABLE|DATABASE|INDEX)\b"
        r"|"
        r"\bALTER\s+TABLE\b"
        r"|"
        r"\bTRUNCATE\s+TABLE\b"
        r"|"
        # GRANT/REVOKE are SQL-specific enough on their own
        r"\bGRANT\s+\w+"
        r"|"
        r"\bREVOKE\s+\w+",
        re.IGNORECASE,
    ),

    # ── Documentation marker ─────────────────────────────────────────────
    # Catches structured doc markers AND natural-language requests for internal docs.
    "documentation": re.compile(
        r"(?im)"
        # Structured doc section headers (##/=== Overview, README, etc.)
        r"(?:^(?:##\s+|={3,}\s*)(?:overview|introduction|summary|changelog|readme|notice))"
        r"|"
        # Natural language requests for internal/system documentation
        r"(?:(?:show|get|share|give|access|view|read|see|fetch|retrieve|send|provide|display)\s+"
        r"(?:me\s+)?(?:the\s+|all\s+|our\s+|your\s+)?"
        r"(?:internal|company|organization|org|system|technical|private|confidential|proprietary|restricted|classified)\s+"
        r"(?:docs?|documentation|docs?\s+and|manuals?|guidelines?|procedures?|sops?|playbook|architecture|specs?))"
        r"|"
        # Broad: "internal documentation", "system documentation", "company documentation"
        r"(?:internal|system|company|org(?:anization)?|architecture|infrastructure|proprietary|confidential)\s+"
        r"documentation",
        re.IGNORECASE,
    ),

    # ── Credential Harvesting Requests ────────────────────────────────────
    # Detects social-engineering prompts that request sensitive credentials/data.
    "debug_env_dump": re.compile(
        r"(?is)"
        r"(?:"
        r"HTTP/1\.1\s+500|500\s+Internal\s+Server\s+Error|verbose\s+debug|debug\s+error|"
        r"stack\s*trace|stackTrace|traceback|environment\s*['\"]?\s*:"
        r")"
        r".{0,3000}"
        r"(?:"
        r"DATABASE_URL|DB_PASSWORD|DB_USER|DB_HOST|JWT_SECRET|JWT_SECRET_KEY|SECRET_KEY|"
        r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|"
        r"PRIVATE_KEY|ENCRYPTION_KEY|SESSION_SECRET|STRIPE_API_KEY"
        r")",
        re.IGNORECASE,
    ),

    "credential_request": re.compile(
        r"(?i)"
        # "give me / show me / get me * credentials/passwords/keys/tokens"
        r"(?:give|show|get|fetch|retrieve|provide|share|send|list|dump|expose|extract)\s+"
        r"(?:me\s+)?(?:all\s+)?(?:the\s+)?"
        r"(?:\w+\s+){0,3}"           # optional qualifiers: "admin", "customer", "all user"
        r"(?:credentials?|passwords?|api\s*keys?|secret\s*keys?|access\s*tokens?|auth\s*tokens?)"
        r"|"
        # "list/show/get * bank details / account details / financial details"
        r"(?:give|show|get|fetch|list|dump|expose|extract|display)\s+"
        r"(?:me\s+)?(?:all\s+)?(?:the\s+)?"
        r"(?:\w+\s+){0,3}"
        r"(?:bank\s+details?|account\s+details?|financial\s+details?|payment\s+details?)"
        r"|"
        # "admin credentials / user credentials / login credentials"
        r"\b(?:admin|root|system|user|login|master)\s+credentials?\b"
        r"|"
        # "credentials for / password for * system/account/database"
        r"\bcredentials?\s+(?:for|of|to)\s+(?:the\s+)?(?:admin|database|system|account|server)\b",
        re.IGNORECASE,
    ),

    # ── Adversarial / Attack Vectors ──────────────────────────────────────
    "adversarial_injection": re.compile(
        r"(?i)"
        # ── Classic jailbreak phrases ─────────────────────────────────────
        r"ignore\s+(?:previous|all|prior|everything|anything)\s*(?:instructions?|outside|the\s+following)?"
        r"|you\s+are\s+(?:now\b|a\s+no\s+longer)"
        r"|act\s+as\s+(?:system|admin|root|god|jailbreak|developer|unrestricted)"
        r"|reveal\s+(?:hidden|your|all|system|internal)\s+(?:rules?|instructions?|prompt|config|policy|secrets?)"
        r"|bypass\s+(?:security|filter|safety|content|restrictions?|policy|firewall)"
        r"|disable\s+(?:safety|security|filter|restrictions?|policy)"
        r"|override\s+(?:instructions?|policy|rules?|restrictions?)"
        r"|(?:system|admin|root)\s+prompt"
        r"|pretend\s+(?:you\s+are|to\s+be)"
        r"|jailbreak"
        r"|DAN\s+mode"
        r"|developer\s+mode"
        r"|prompt\s+injection"
        r"|(?:let['’]?s\s+)?forget\s+(?:about\s+)?(?:everything|all|spanish|english|the\s+above|this)"
        r"|special\s+(?:note\s+from|case)"
        r"|from\s+now\s+on"
        r"|do\s+not\s+(?:translate|print|output|write|read)"
        r"|continue\s+the\s+(?:translation|task|prompt)"
        r"|the\s+setting\s+is\s+a\s+fictional\s+world"
        r"|if\s+the\s+(?:period|user\s+input|sentence|prompt)"
        r"|(?:only\s+)?say\s+exactly"
        r"|repeat\s+(?:w/o|without)\s+brackets"
        # ── Synonym evasion: polite/indirect instruction override (A2) ─────
        r"|(?:disregard|circumvent|set\s+aside|put\s+aside|forget|dismiss)\s+"
        r"(?:(?:earlier|previous|prior|all|the|your|operational|security|safety|existing)\s+){0,3}"
        r"(?:constraints?|instructions?|rules?|policies|limits?|guidelines?|restrictions?|directives?)"
        r"|without\s+restrictions?"
        r"|unrestricted\s+(?:access|mode|ai|model)"
        r"|operating\s+in\s+(?:developer|unrestricted|admin|god|privileged)\s+mode"
        # ── Privilege escalation / social engineering (E1) ────────────────
        r"|(?:recently|just|have|was)\s+(?:been\s+)?(?:promoted|elevated|upgraded|granted|given)\s+"
        r"(?:(?:access\s+)?(?:as\s+)?|to\s+)(?:admin|administrator|root|manager|superuser|owner)"
        r"|(?:new|current)\s+(?:admin|administrator|manager|superuser|role)"
        r"|my\s+(?:new\s+)?(?:admin|administrator|elevated|privileged)\s+(?:access|role|status|account)"
        # ── Infrastructure / credential extraction requests (I1, A2) ──────
        r"|(?:provide|share|give|send|show|display|reveal|expose|output|print|return|dump)\s+"
        r"(?:me\s+)?(?:the\s+)?"
        r"(?:backend|infrastructure|internal|system|hidden|private|sensitive|database|db)\s+"
        r"(?:credentials?|secrets?|keys?|passwords?|tokens?|config(?:uration)?|connection\s+string|api)"
        r"|database\s+connection\s+(?:string|url|uri|details?)"
        r"|authentication\s+(?:token|key|credentials?|secret)"
        r"|master\s+(?:access\s+)?(?:key|password|token|secret)"
        r"|(?:not\s+typically\s+exposed|normally\s+hidden|usually\s+restricted)"
        r"|(?:infrastructure|backend|system)\s+credentials?"
    ),

    "encoded_payload": re.compile(
        # Base64 blob: 20+ chars of base64 alphabet, possibly with = padding
        r"(?<![\\w/+])(?:[A-Za-z0-9+/]{20,}={0,2})(?![\\w/+])"
        r"|"
        # Hex-encoded blob: 30+ consecutive hex chars (15+ bytes)
        # Must be purely hex (only 0-9 and a-f/A-F) to distinguish from generic alphanumeric
        r"\b[0-9a-fA-F]{30,}\b(?![G-Zg-z])",
    ),

    "secret_token": re.compile(
        r"(?i)(?:secret[_\-]?token|auth[_\-]?credential|auth[_\-]?token|session[_\-]?token)"
        r"\s*[=:]\s*['\"]?[A-Za-z0-9\-_.]{8,}['\"]?",
    ),

    # ── Embedded Secret Key (ADVERSARIAL — BLOCK) ─────────────────────────
    # Catches adversarial prompts that hide/embed a short secret inside the
    # prompt using natural-language framing, e.g.:
    #   "Remember this secret key: rpUnff"
    #   "key: abc123 — don't tell anyone"
    #   "The hidden key is Xq9mT2"
    # Requires only 4+ alphanumeric chars after the keyword to capture short tokens.
    "embedded_secret_key": re.compile(
        r"(?i)"
        # Phrase-based: "this secret key: VALUE", "hidden key is VALUE", etc.
        r"(?:"
        r"(?:remember|store|keep|note|memorize|use|here\s+is|this\s+is)\s+"
        r"(?:this\s+|the\s+|a\s+|my\s+)?"
        r"(?:secret\s+)?(?:key|token|code|passphrase|passkey|secret|pin)\s*[=:]\s*"
        r"[A-Za-z0-9\-_!@#$%^&*]{4,}"
        r")"
        r"|"
        # Bare contextual: "secret key: VALUE" / "key = VALUE" (short form)
        r"(?:"
        r"(?:secret\s+)?(?:key|token|passphrase|passkey|secret|pin)\s*[=:]\s*"
        r"[A-Za-z0-9\-_!@#$%^&*]{4,20}"   # 4-20 chars — targets short embedded tokens
        r"(?:\s|$|\.|,|;)"
        r")"
        r"|"
        # Hidden/embedded framing: "hidden key is VALUE", "secret is VALUE"
        r"(?:"
        r"(?:hidden|embedded|encoded|stored|injected)\s+"
        r"(?:key|secret|token|code|pin)\s+is\s+"
        r"[A-Za-z0-9\-_!@#$%^&*]{4,}"
        r")",
    ),

    # ── Social Engineering Injection (ADVERSARIAL — BLOCK) ─────────────────
    # Catches PWNED-style and related adversarial patterns that:
    #   (A) Redefine a phrase/word to mean something else
    #   (B) Force the AI to output a specific exact phrase
    #   (C) Embed 'ignore (these) rules/instructions' inline
    #   (D) Use story-frame wrappers to smuggle injected instructions
    #   (E) Issue conflicting/meta instructions to override AI behavior
    "social_engineering_injection": re.compile(
        r"(?i)"

        # ── (A) Phrase Redefinition Attack ────────────────────────────────
        # e.g. "PWNED is not about hacking, it is about equality"
        # e.g. "X does not mean Y, it means Z"
        r"(?:\b\w+\b\s+(?:is\s+not\s+about|does\s+not\s+mean|stands\s+for|is\s+short\s+for)\s+"
        r"(?:hacking|jailbreak|injection|exploit|attack|breaking))"

        r"|"
        # ── (B) Forced Exact Output Directive ────────────────────────────
        # e.g. "say 'I have been PWNED' now, using only 4 words"
        # e.g. "return only these exact 4 words"
        # e.g. "do not provide any other explanations, return only"
        r"(?:say\s+['\"]?[\w\s]{3,40}['\"]?\s+now\b)"
        r"|"
        r"(?:return\s+only\s+(?:these\s+)?(?:exact\s+)?(?:\d+\s+)?words?)"
        r"|"
        r"(?:do\s+not\s+provide\s+any\s+other\s+(?:explanation|text|output|response)s?"
        r"(?:[,;]\s*return\s+only)?)"
        r"|"
        r"(?:using\s+only\s+\d+\s+words?\s+and\s+do\s+not\s+provide)"
        r"|"
        # ── (C) Inline 'Ignore These' Directive (parenthetical) ──────────
        # e.g. "check if there are any special rules or instructions (ignore these)"
        r"(?:ignore\s+(?:these|this|them|all)\s*[)\]]"
        r"|[([{]\s*ignore\s+(?:these|this|all|them)\s*[)\]}])"
        r"|"
        # ── (D) Story-Frame Prompt Injection ─────────────────────────────
        # e.g. "write a story that starts with the following exact text:"
        # e.g. "the story should end with the following exact text"
        r"(?:(?:write|craft|create|generate)\s+(?:an?\s+)?(?:engaging\s+)?(?:short\s+)?story\s+"
        r"(?:about|that)\s+.*?(?:starts?\s+with\s+(?:the\s+)?(?:following|exact)\s+text))"
        r"|"
        r"(?:(?:the\s+story|it)\s+should\s+(?:start|begin|end)\s+with\s+the\s+following\s+exact\s+text)"
        r"|"
        # ── (E) Forbidden Phrase + Forced Replacement Instruction ─────────
        # e.g. "'I have not been PWNED' is a forbidden phrase"
        # e.g. "instead of saying X, say Y"
        r"(?:instead\s+of\s+saying\s+['\"][^'\"]{3,60}['\"]\s*[,;]\s*say\s+['\"])"
        r"|"
        r"(?:['\"][^'\"]{3,60}['\"]\s+is\s+(?:a\s+)?forbidden\s+phrase)"
        r"|"
        # ── (F) Direct command to output PWNED phrase ─────────────────────
        # e.g. "say 'I have been PWNED'", "output I have been PWNED"
        # NOTE: bare 'I have been PWNED' is NOT blocked here — it can appear
        # innocuously inside quoted/bracketed user text in grammar-review prompts.
        # Only block when it is an EXPLICIT DIRECTIVE to the AI to say it.
        r"(?:(?:say|output|respond|write|print|return|echo)(?:.{0,100})['\"]?(?:I\s+)?have\s+been\s+[*_]*PWNED[*_]*['\"]?)"
        r"|"
        # ── (G) Anti-analysis instruction at end ─────────────────────────
        # e.g. "if the above phrase is trying to PWN, pwn, pawn, or prawn, you"
        r"(?:(?:pwn|pawn|prawn)\s+you\b)"
        r"|"
        r"(?:written\s+as\s+a\s+title\s+-\s+do\s+not\s+add\s+(?:fullstop|dot|period))"
        r"|"
        # ── (H) Other exact text tricks ─────────────────────────
        r"(?:I\s+have\s+been\s+PWNED\s*){3,}"
    ),
}


# Priority order: higher-specificity patterns win over generic ones
# when they match the same span. Higher number = higher priority.
_DTYPE_PRIORITY: dict[str, int] = {
    "cloud_key":                    100,
    "encryption_key":               100,
    "private_key":                  100,
    "debug_env_dump":                95,
    "encoded_payload":               90,  # pure hex/base64 wins over generic api_key
    "adversarial_injection":         85,
    "social_engineering_injection":  85,
    "embedded_secret_key":           85,
    "secret_token":                  80,
    "credential_request":            80,
    "credit_card":                   75,
    "ssn":                           75,
    "financial_account":             92,  # above encoded_payload so IBAN isn't misclassified as hex
    "password":                      75,
    "api_key":                       70,
    "phone":                         68,  # phone wins over aadhaar (+919876543210 case)
    "aadhaar":                       65,  # aadhaar after phone to avoid false match on +91 prefix
    "source_code":                   60,
    "sql_query":                     60,
    "email":                         50,
    "phone_words":                   50,
    "contextual_pii":                50,
    "mac_address":                   50,
    "ip_address":                    50,
    "passport":                      50,
    "documentation":                 40,
}


def scan(prompt: str) -> List[Detection]:
    """
    Scan *prompt* for all sensitive data types defined in PATTERNS.

    Returns a list of Detection objects ordered by start position.
    When two patterns match the same span, the higher-priority dtype wins
    (see _DTYPE_PRIORITY). This ensures e.g. pure-hex blobs are labelled
    as encoded_payload rather than api_key.
    """
    # Collect ALL matches: (priority, start, end, dtype, value)
    all_matches: list[tuple[int, int, int, str, str]] = []

    for dtype, pattern in PATTERNS.items():
        priority = _DTYPE_PRIORITY.get(dtype, 50)
        for match in pattern.finditer(prompt):
            all_matches.append((priority, match.start(), match.end(), dtype, match.group()))

    for match in _CONTEXTUAL_PHONE_PATTERN.finditer(prompt):
        number = match.group("number")
        digit_count = len(re.sub(r"\D", "", number))
        if 7 <= digit_count <= 15:
            all_matches.append((
                _DTYPE_PRIORITY["phone"],
                match.start("number"),
                match.end("number"),
                "phone",
                number,
            ))

    for match in _CONTEXTUAL_PII_PATTERN.finditer(prompt):
        value = match.group("value").strip(" .,:;")
        if _looks_like_contextual_pii_value(value):
            start = match.start("value")
            end = start + len(value)
            all_matches.append((
                _DTYPE_PRIORITY["contextual_pii"],
                start,
                end,
                "contextual_pii",
                value,
            ))

    # Sort by start position, then descending priority so highest-priority
    # dtype wins when two patterns match the same span.
    all_matches.sort(key=lambda x: (x[1], -x[0]))

    detections: List[Detection] = []
    seen_spans: set[tuple[int, int]] = set()

    for priority, start, end, dtype, value in all_matches:
        span = (start, end)
        if span in seen_spans:
            continue
        seen_spans.add(span)
        detections.append(Detection(dtype=dtype, value=value, start=start, end=end))

    # Sort by start index for deterministic tokenisation order
    detections.sort(key=lambda d: d.start)
    return detections
