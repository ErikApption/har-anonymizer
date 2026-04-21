# har-anonymizer

Anonymize HAR captures exported from Chrome or Edge before sharing them with
AI tools (Copilot, ChatGPT, …) to generate automation scripts.  
It replaces all cookies, auth tokens, passwords, credit-card numbers, SSNs, and
other sensitive data with `[REDACTED]` so that no banking or personal
information leaks.

---

## Installation

```bash
pip install har-anonymizer        # from PyPI once published
# – or –
pip install .                     # from a local clone
```

Requires Python ≥ 3.9.

---

## Usage

```
har-anonymizer INPUT [OUTPUT] [--redact-emails] [--redact-ips] [--indent N]
```

| Argument | Description |
|---|---|
| `INPUT` | Path to the source `.har` file |
| `OUTPUT` | *(optional)* Output path. Defaults to `<stem>.anonymized.har` next to the input |
| `--redact-emails` | Also replace e-mail addresses with `[REDACTED]` |
| `--redact-ips` | Replace IPv4 addresses (including `serverIPAddress`) with `0.0.0.0` |
| `--indent N` | JSON indentation of the output file (default `2`) |

### Example

```bash
# Capture a banking session in Chrome (DevTools → Network → Export HAR)
har-anonymizer banking_session.har --redact-emails --redact-ips
# → writes banking_session.anonymized.har
```

---

## What is anonymized

| Location | What is replaced |
|---|---|
| Request / response **headers** | `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-Access-Token`, `X-CSRF-Token`, `Proxy-Authorization`, and more |
| **Cookies** | All cookie *values* (names are preserved) |
| **Query-string parameters** | `password`, `token`, `access_token`, `api_key`, `secret`, `session_id`, and similar |
| **POST form parameters** | Same list as query-string |
| **JSON request/response bodies** | Recursive key scan: `password`, `token`, `access_token`, `card_number`, `ssn`, `email`, `username`, `phone`, `address`, and more |
| **All body text** | Credit-card numbers (Visa/MC/Amex/Discover), US SSNs (`XXX-XX-XXXX`), Bearer tokens |
| `serverIPAddress` | Removed by default; replaced with `0.0.0.0` with `--redact-ips` |
| Creator/browser **comments** | Removed |
| *(optional)* **E-mail addresses** | `--redact-emails` |
| *(optional)* **IPv4 addresses in bodies** | `--redact-ips` |

Non-sensitive fields (URLs, HTTP methods, status codes, timing, non-secret
headers such as `Content-Type`) are left intact so that automation scripts
generated from the HAR remain accurate.

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"          # or: poetry install

# Run tests
pytest
```

The project uses [Poetry](https://python-poetry.org/) for packaging.
