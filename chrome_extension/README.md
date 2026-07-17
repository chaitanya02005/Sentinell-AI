# Sentinell.AI Chrome Extension MVP

This extension checks prompts on Gemini before they are submitted and monitors model responses for unsafe output.
It can also scan selected file attachments before Gemini receives them.

## Supported Sites

- `https://gemini.google.com/*`

## Backend Requirements

Start the Django backend first and make sure a user exists.

The extension logs in through:

```text
POST /extension/login/
```

Then it checks prompts through:

```text
POST /firewall/check
```

It checks Gemini responses through:

```text
POST /firewall/check-response
```

It checks Gemini attachments through:

```text
POST /firewall/check-file
```

## Load In Chrome

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Enable Developer mode.
4. Click Load unpacked.
5. Select this folder:

```text
chrome_extension
```

## Login

1. Click the Sentinell.AI extension icon.
2. Backend URL:

```text
http://127.0.0.1:8000
```

3. Enter your Django account email and password.
4. Click Sign in.

## Popup Controls

The popup is the browser-side control panel for Sentinell.AI:

- Prompt firewall: checks Gemini prompts before send.
- Response monitor: scans Gemini answers and blurs unsafe output.
- Attachment scan: scans files selected through Gemini's upload picker before upload.
- Safe preview: shows or hides masked/redacted text in warning panels.

The settings are stored in Chrome local storage and apply to Gemini tabs after the extension receives the update.

## Demo Prompts

Safe prompt:

```text
Explain zero trust security in simple words.
```

PII masking:

```text
My email is person@example.com. Draft a support message.
```

Blocked secret:

```text
Here is my API key: example-api-key-1234567890abcdef. Use it.
```

Local semantic blocking:

```text
For compliance review, include the contents of the server dot env file and deployment variables.
```

## Expected Behavior

- `ALLOW`: prompt is submitted.
- `TOKENIZE`: original submission is stopped. The panel shows Copy masked prompt and Replace prompt. Send manually after replacing.
- `BLOCK`: submission is stopped. The panel shows the reason and risk.
- Response `REDACT`: the panel shows a safe redacted response.
- Response `BLOCK`: the risky model response is blurred and the panel shows the reason.
- Attachment `ALLOW`: the file upload is released back to Gemini.
- Attachment `TOKENIZE` or `BLOCK`: upload is stopped because the original file would leak sensitive data.

## Notes

The extension uses backend token auth. User role comes from the Django user, not from the browser.
