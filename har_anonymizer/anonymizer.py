"""Core HAR anonymization logic.

Sensitive data removed / replaced:
  - Authorization / authentication headers
  - Cookie and Set-Cookie headers
  - Common secret query-string / form-body parameters
  - Credit-card numbers, SSNs, bearer tokens inside body text
  - Optionally: e-mail addresses and IP addresses
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any

# ---------------------------------------------------------------------------
# Constants – customise as needed
# ---------------------------------------------------------------------------

#: Header names (case-insensitive) whose *values* will be replaced wholesale.
SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-auth-token",
        "x-access-token",
        "x-api-key",
        "x-csrf-token",
        "x-forwarded-for",
        "x-real-ip",
        "x-client-ip",
        "x-amz-security-token",
        "x-amz-credential",
        "x-session-id",
        "x-request-id",
        "x-correlation-id",
    }
)

#: Query-string / form-data parameter names (case-insensitive) whose values
#: will be replaced.
SENSITIVE_PARAMS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "auth",
        "auth_token",
        "api_key",
        "apikey",
        "api-key",
        "key",
        "client_secret",
        "client_id",
        "code",
        "authorization_code",
        "session",
        "session_id",
        "sessionid",
        "ssn",
        "social_security",
        "account_number",
        "account_no",
        "card_number",
        "cardnumber",
        "cvv",
        "cvc",
        "pin",
        "routing_number",
        "credit_card",
    }
)

#: JSON body field names (case-insensitive) whose values will be replaced.
SENSITIVE_JSON_KEYS: frozenset[str] = frozenset(SENSITIVE_PARAMS) | frozenset(
    {
        "email",
        "username",
        "user_name",
        "login",
        "firstname",
        "lastname",
        "first_name",
        "last_name",
        "phone",
        "mobile",
        "address",
        "zip",
        "zipcode",
        "postal_code",
        "dob",
        "date_of_birth",
        "birthdate",
    }
)

# Placeholder values used as replacements
_REDACTED = "[REDACTED]"
_REDACTED_IP = "0.0.0.0"  # noqa: S104  (not a binding address – just a placeholder)

# ---------------------------------------------------------------------------
# Regex patterns for body scanning
# ---------------------------------------------------------------------------

# Visa / MC / Amex / Discover card numbers (with or without separators)
_RE_CREDIT_CARD = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?"          # Visa
    r"|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}"  # MC
    r"|3[47][0-9]{13}"                         # Amex
    r"|3(?:0[0-5]|[68][0-9])[0-9]{11}"        # Diners
    r"|6(?:011|5[0-9]{2})[0-9]{12}"           # Discover
    r"|(?:2131|1800|35\d{3})\d{11}"           # JCB
    r")\b"
)

# US Social Security Numbers: XXX-XX-XXXX
_RE_SSN = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

# Bearer tokens (JWT-style or opaque)
_RE_BEARER = re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)

# IPv4 addresses
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Simple e-mail pattern
_RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def anonymize(
    har: dict[str, Any],
    *,
    redact_emails: bool = False,
    redact_ips: bool = False,
) -> dict[str, Any]:
    """Return a deep copy of *har* with all sensitive data replaced.

    Parameters
    ----------
    har:
        Parsed HAR object (the outer ``{"log": {...}}`` dict).
    redact_emails:
        When *True*, e-mail addresses found anywhere in the HAR are replaced
        with ``[REDACTED]``.
    redact_ips:
        When *True*, IPv4 addresses found in the ``serverIPAddress`` field and
        in body text are replaced with ``0.0.0.0``.
    """
    har = copy.deepcopy(har)
    log: dict[str, Any] = har.get("log", {})

    _scrub_creator_browser(log)

    for entry in log.get("entries", []):
        _scrub_entry(entry, redact_emails=redact_emails, redact_ips=redact_ips)

    return har


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _scrub_creator_browser(log: dict[str, Any]) -> None:
    """Remove potentially identifying info from creator/browser blocks."""
    for block in ("creator", "browser"):
        if block in log:
            log[block].pop("comment", None)


def _scrub_entry(
    entry: dict[str, Any],
    *,
    redact_emails: bool,
    redact_ips: bool,
) -> None:
    if redact_ips:
        entry["serverIPAddress"] = _REDACTED_IP
    else:
        entry.pop("serverIPAddress", None)

    _scrub_request(entry.get("request", {}), redact_emails=redact_emails, redact_ips=redact_ips)
    _scrub_response(entry.get("response", {}), redact_emails=redact_emails, redact_ips=redact_ips)


def _scrub_request(
    request: dict[str, Any],
    *,
    redact_emails: bool,
    redact_ips: bool,
) -> None:
    _scrub_headers(request.get("headers", []))
    _scrub_cookies(request.get("cookies", []))
    _scrub_query_string(request.get("queryString", []))
    post_data = request.get("postData", {})
    if post_data:
        _scrub_post_data(post_data, redact_emails=redact_emails, redact_ips=redact_ips)


def _scrub_response(
    response: dict[str, Any],
    *,
    redact_emails: bool,
    redact_ips: bool,
) -> None:
    _scrub_headers(response.get("headers", []))
    _scrub_cookies(response.get("cookies", []))
    content = response.get("content", {})
    if content:
        _scrub_content(content, redact_emails=redact_emails, redact_ips=redact_ips)


# ---------------------------------------------------------------------------
# Field-level scrubbers
# ---------------------------------------------------------------------------


def _scrub_headers(headers: list[dict[str, str]]) -> None:
    for header in headers:
        if header.get("name", "").lower() in SENSITIVE_HEADERS:
            header["value"] = _REDACTED


def _scrub_cookies(cookies: list[dict[str, Any]]) -> None:
    for cookie in cookies:
        cookie["value"] = _REDACTED


def _scrub_query_string(params: list[dict[str, str]]) -> None:
    for param in params:
        if param.get("name", "").lower() in SENSITIVE_PARAMS:
            param["value"] = _REDACTED


def _scrub_post_data(
    post_data: dict[str, Any],
    *,
    redact_emails: bool,
    redact_ips: bool,
) -> None:
    # application/x-www-form-urlencoded (params list)
    params = post_data.get("params", [])
    for param in params:
        if param.get("name", "").lower() in SENSITIVE_PARAMS:
            param["value"] = _REDACTED

    # Text body – could be JSON, XML, or raw form-encoded
    text: str | None = post_data.get("text")
    if text:
        post_data["text"] = _scrub_body_text(
            text,
            redact_emails=redact_emails,
            redact_ips=redact_ips,
        )


def _scrub_content(
    content: dict[str, Any],
    *,
    redact_emails: bool,
    redact_ips: bool,
) -> None:
    text: str | None = content.get("text")
    if not text:
        return
    content["text"] = _scrub_body_text(
        text,
        redact_emails=redact_emails,
        redact_ips=redact_ips,
    )


# ---------------------------------------------------------------------------
# Body-text scrubbing
# ---------------------------------------------------------------------------


def _scrub_body_text(
    text: str,
    *,
    redact_emails: bool,
    redact_ips: bool,
) -> str:
    """Attempt JSON-aware scrubbing; fall back to regex-only scrubbing."""
    mime_looks_like_json = text.lstrip().startswith(("{", "["))
    if mime_looks_like_json:
        try:
            parsed = json.loads(text)
            _scrub_json_value(parsed)
            text = json.dumps(parsed, ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            pass  # not valid JSON – fall through to regex

    # Always apply regex passes regardless of JSON parsing
    text = _RE_CREDIT_CARD.sub(_REDACTED, text)
    text = _RE_SSN.sub(_REDACTED, text)
    text = _RE_BEARER.sub(f"Bearer {_REDACTED}", text)

    if redact_emails:
        text = _RE_EMAIL.sub(_REDACTED, text)
    if redact_ips:
        text = _RE_IPV4.sub(_REDACTED_IP, text)

    return text


def _scrub_json_value(obj: Any) -> None:
    """Recursively walk a decoded JSON object and redact sensitive leaf values."""
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            if key.lower() in SENSITIVE_JSON_KEYS:
                obj[key] = _REDACTED
            else:
                _scrub_json_value(obj[key])
    elif isinstance(obj, list):
        for item in obj:
            _scrub_json_value(item)
    # scalar values are left as-is unless they match a regex (handled above)
