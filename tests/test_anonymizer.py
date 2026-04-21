"""Unit tests for the HAR anonymizer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from har_anonymizer.anonymizer import (
    _REDACTED,
    _REDACTED_IP,
    anonymize,
)
from har_anonymizer.cli import build_parser, main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_har(entries: list[dict] | None = None) -> dict:
    """Build a minimal valid HAR dict."""
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "Browser", "version": "1", "comment": "sensitive comment"},
            "browser": {"name": "Chrome", "version": "130", "comment": "another comment"},
            "entries": entries or [],
        }
    }


def _make_entry(
    *,
    request_headers: list[dict] | None = None,
    response_headers: list[dict] | None = None,
    cookies: list[dict] | None = None,
    query_string: list[dict] | None = None,
    post_data: dict | None = None,
    response_content: dict | None = None,
    server_ip: str = "192.168.1.1",
) -> dict:
    entry: dict = {
        "serverIPAddress": server_ip,
        "request": {
            "method": "GET",
            "url": "https://example.com",
            "headers": request_headers or [],
            "cookies": cookies or [],
            "queryString": query_string or [],
        },
        "response": {
            "status": 200,
            "headers": response_headers or [],
            "cookies": [],
            "content": response_content or {"mimeType": "text/plain", "text": ""},
        },
    }
    if post_data is not None:
        entry["request"]["postData"] = post_data
    return entry


# ---------------------------------------------------------------------------
# Header scrubbing
# ---------------------------------------------------------------------------


class TestHeaders:
    def test_authorization_header_redacted(self):
        entry = _make_entry(
            request_headers=[{"name": "Authorization", "value": "Bearer secret_token"}]
        )
        result = anonymize(_make_har([entry]))
        headers = result["log"]["entries"][0]["request"]["headers"]
        assert headers[0]["value"] == _REDACTED

    def test_authorization_header_case_insensitive(self):
        entry = _make_entry(
            request_headers=[{"name": "AUTHORIZATION", "value": "Bearer token123"}]
        )
        result = anonymize(_make_har([entry]))
        assert result["log"]["entries"][0]["request"]["headers"][0]["value"] == _REDACTED

    def test_cookie_header_redacted(self):
        entry = _make_entry(
            request_headers=[{"name": "Cookie", "value": "session=abc123; user=me"}]
        )
        result = anonymize(_make_har([entry]))
        assert result["log"]["entries"][0]["request"]["headers"][0]["value"] == _REDACTED

    def test_set_cookie_response_header_redacted(self):
        entry = _make_entry(
            response_headers=[{"name": "Set-Cookie", "value": "session=xyz; HttpOnly"}]
        )
        result = anonymize(_make_har([entry]))
        assert result["log"]["entries"][0]["response"]["headers"][0]["value"] == _REDACTED

    def test_non_sensitive_header_preserved(self):
        entry = _make_entry(
            request_headers=[{"name": "Content-Type", "value": "application/json"}]
        )
        result = anonymize(_make_har([entry]))
        assert result["log"]["entries"][0]["request"]["headers"][0]["value"] == "application/json"

    def test_x_api_key_redacted(self):
        entry = _make_entry(
            request_headers=[{"name": "X-Api-Key", "value": "my-secret-key-12345"}]
        )
        result = anonymize(_make_har([entry]))
        assert result["log"]["entries"][0]["request"]["headers"][0]["value"] == _REDACTED


# ---------------------------------------------------------------------------
# Cookie scrubbing
# ---------------------------------------------------------------------------


class TestCookies:
    def test_request_cookies_redacted(self):
        entry = _make_entry(
            cookies=[{"name": "session", "value": "abc123"}, {"name": "pref", "value": "dark"}]
        )
        result = anonymize(_make_har([entry]))
        for cookie in result["log"]["entries"][0]["request"]["cookies"]:
            assert cookie["value"] == _REDACTED

    def test_cookie_names_preserved(self):
        entry = _make_entry(cookies=[{"name": "JSESSIONID", "value": "secret"}])
        result = anonymize(_make_har([entry]))
        assert result["log"]["entries"][0]["request"]["cookies"][0]["name"] == "JSESSIONID"


# ---------------------------------------------------------------------------
# Query string scrubbing
# ---------------------------------------------------------------------------


class TestQueryString:
    def test_password_param_redacted(self):
        entry = _make_entry(
            query_string=[{"name": "password", "value": "hunter2"}]
        )
        result = anonymize(_make_har([entry]))
        assert result["log"]["entries"][0]["request"]["queryString"][0]["value"] == _REDACTED

    def test_token_param_redacted(self):
        entry = _make_entry(query_string=[{"name": "token", "value": "abc"}])
        result = anonymize(_make_har([entry]))
        assert result["log"]["entries"][0]["request"]["queryString"][0]["value"] == _REDACTED

    def test_non_sensitive_param_preserved(self):
        entry = _make_entry(query_string=[{"name": "page", "value": "2"}])
        result = anonymize(_make_har([entry]))
        assert result["log"]["entries"][0]["request"]["queryString"][0]["value"] == "2"


# ---------------------------------------------------------------------------
# POST data scrubbing
# ---------------------------------------------------------------------------


class TestPostData:
    def test_form_params_redacted(self):
        entry = _make_entry(
            post_data={
                "mimeType": "application/x-www-form-urlencoded",
                "params": [
                    {"name": "username", "value": "alice"},
                    {"name": "password", "value": "s3cr3t"},
                ],
                "text": "username=alice&password=s3cr3t",
            }
        )
        result = anonymize(_make_har([entry]))
        params = result["log"]["entries"][0]["request"]["postData"]["params"]
        # username is NOT in SENSITIVE_PARAMS but password is
        pw = next(p for p in params if p["name"] == "password")
        assert pw["value"] == _REDACTED

    def test_json_body_redacted(self):
        body = json.dumps({"password": "topsecret", "username": "bob"})
        entry = _make_entry(
            post_data={"mimeType": "application/json", "text": body}
        )
        result = anonymize(_make_har([entry]))
        text = result["log"]["entries"][0]["request"]["postData"]["text"]
        parsed = json.loads(text)
        assert parsed["password"] == _REDACTED

    def test_credit_card_in_body_redacted(self):
        body = json.dumps({"cardNumber": "4111111111111111", "amount": 100})
        entry = _make_entry(post_data={"mimeType": "application/json", "text": body})
        result = anonymize(_make_har([entry]))
        text = result["log"]["entries"][0]["request"]["postData"]["text"]
        assert "4111111111111111" not in text

    def test_ssn_in_plain_body_redacted(self):
        body = "My SSN is 123-45-6789 please process"
        entry = _make_entry(post_data={"mimeType": "text/plain", "text": body})
        result = anonymize(_make_har([entry]))
        text = result["log"]["entries"][0]["request"]["postData"]["text"]
        assert "123-45-6789" not in text

    def test_bearer_token_in_body_redacted(self):
        body = '{"token": "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig"}'
        entry = _make_entry(post_data={"mimeType": "application/json", "text": body})
        result = anonymize(_make_har([entry]))
        text = result["log"]["entries"][0]["request"]["postData"]["text"]
        # The "token" key is in SENSITIVE_JSON_KEYS so value is redacted
        assert "eyJhbGciOiJSUzI1NiJ9" not in text


# ---------------------------------------------------------------------------
# Response content scrubbing
# ---------------------------------------------------------------------------


class TestResponseContent:
    def test_json_response_password_field_redacted(self):
        body = json.dumps({"access_token": "supersecret", "expires_in": 3600})
        entry = _make_entry(
            response_content={"mimeType": "application/json", "text": body}
        )
        result = anonymize(_make_har([entry]))
        text = result["log"]["entries"][0]["response"]["content"]["text"]
        parsed = json.loads(text)
        assert parsed["access_token"] == _REDACTED
        assert parsed["expires_in"] == 3600  # non-sensitive fields preserved

    def test_credit_card_in_response_redacted(self):
        body = f"Your card ending in 4111111111111111 was charged."
        entry = _make_entry(response_content={"mimeType": "text/html", "text": body})
        result = anonymize(_make_har([entry]))
        text = result["log"]["entries"][0]["response"]["content"]["text"]
        assert "4111111111111111" not in text


# ---------------------------------------------------------------------------
# Email and IP redaction (optional flags)
# ---------------------------------------------------------------------------


class TestOptionalRedaction:
    def test_email_redacted_when_flag_set(self):
        body = "Contact us at support@example.com for help."
        entry = _make_entry(post_data={"mimeType": "text/plain", "text": body})
        result = anonymize(_make_har([entry]), redact_emails=True)
        text = result["log"]["entries"][0]["request"]["postData"]["text"]
        assert "support@example.com" not in text

    def test_email_preserved_when_flag_not_set(self):
        body = "Contact us at support@example.com for help."
        entry = _make_entry(post_data={"mimeType": "text/plain", "text": body})
        result = anonymize(_make_har([entry]), redact_emails=False)
        text = result["log"]["entries"][0]["request"]["postData"]["text"]
        assert "support@example.com" in text

    def test_server_ip_removed_by_default(self):
        entry = _make_entry(server_ip="203.0.113.42")
        result = anonymize(_make_har([entry]))
        assert "serverIPAddress" not in result["log"]["entries"][0]

    def test_server_ip_replaced_when_flag_set(self):
        entry = _make_entry(server_ip="203.0.113.42")
        result = anonymize(_make_har([entry]), redact_ips=True)
        assert result["log"]["entries"][0]["serverIPAddress"] == _REDACTED_IP

    def test_ip_in_body_redacted_when_flag_set(self):
        body = "User logged in from 192.168.1.100"
        entry = _make_entry(post_data={"mimeType": "text/plain", "text": body})
        result = anonymize(_make_har([entry]), redact_ips=True)
        text = result["log"]["entries"][0]["request"]["postData"]["text"]
        assert "192.168.1.100" not in text


# ---------------------------------------------------------------------------
# Creator/browser comment scrubbing
# ---------------------------------------------------------------------------


class TestCreatorBrowser:
    def test_creator_comment_removed(self):
        result = anonymize(_make_har([]))
        assert "comment" not in result["log"]["creator"]

    def test_browser_comment_removed(self):
        result = anonymize(_make_har([]))
        assert "comment" not in result["log"]["browser"]


# ---------------------------------------------------------------------------
# Deep-copy safety
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_original_har_not_mutated(self):
        body = json.dumps({"password": "original"})
        entry = _make_entry(post_data={"mimeType": "application/json", "text": body})
        har = _make_har([entry])
        _ = anonymize(har)
        original_text = har["log"]["entries"][0]["request"]["postData"]["text"]
        assert "original" in original_text


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestCLI:
    def test_help(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0

    def test_missing_input_file(self, tmp_path):
        result = main([str(tmp_path / "nonexistent.har")])
        assert result == 1

    def test_end_to_end(self, tmp_path):
        har = _make_har(
            [
                _make_entry(
                    request_headers=[{"name": "Authorization", "value": "Bearer tok"}],
                    cookies=[{"name": "session", "value": "s3cr3t"}],
                    query_string=[{"name": "token", "value": "abc"}],
                )
            ]
        )
        input_file = tmp_path / "test.har"
        input_file.write_text(json.dumps(har), encoding="utf-8")
        output_file = tmp_path / "out.har"

        rc = main([str(input_file), str(output_file)])
        assert rc == 0
        assert output_file.exists()

        result = json.loads(output_file.read_text())
        entry = result["log"]["entries"][0]
        assert entry["request"]["headers"][0]["value"] == _REDACTED
        assert entry["request"]["cookies"][0]["value"] == _REDACTED
        assert entry["request"]["queryString"][0]["value"] == _REDACTED

    def test_default_output_filename(self, tmp_path):
        har = _make_har([])
        input_file = tmp_path / "capture.har"
        input_file.write_text(json.dumps(har), encoding="utf-8")

        rc = main([str(input_file)])
        assert rc == 0
        expected = tmp_path / "capture.anonymized.har"
        assert expected.exists()

    def test_invalid_json_input(self, tmp_path):
        bad_file = tmp_path / "bad.har"
        bad_file.write_text("this is not json", encoding="utf-8")
        result = main([str(bad_file)])
        assert result == 1

    def test_redact_emails_flag(self, tmp_path):
        body = "user@bank.com is the account holder"
        har = _make_har(
            [_make_entry(post_data={"mimeType": "text/plain", "text": body})]
        )
        input_file = tmp_path / "email.har"
        input_file.write_text(json.dumps(har), encoding="utf-8")
        output_file = tmp_path / "email_out.har"

        rc = main([str(input_file), str(output_file), "--redact-emails"])
        assert rc == 0
        result = json.loads(output_file.read_text())
        text = result["log"]["entries"][0]["request"]["postData"]["text"]
        assert "user@bank.com" not in text

    def test_redact_ips_flag(self, tmp_path):
        har = _make_har([_make_entry(server_ip="10.0.0.1")])
        input_file = tmp_path / "ip.har"
        input_file.write_text(json.dumps(har), encoding="utf-8")
        output_file = tmp_path / "ip_out.har"

        rc = main([str(input_file), str(output_file), "--redact-ips"])
        assert rc == 0
        result = json.loads(output_file.read_text())
        assert result["log"]["entries"][0]["serverIPAddress"] == _REDACTED_IP
