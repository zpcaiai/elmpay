"""B22 — the handful of checks that turn baseline text into running code.

Four things, chosen because each one is a control that is easy to *claim* and
easy to get wrong:

* :func:`redact` — a stack trace is the most reliable way for a card number or
  an API key to reach a log aggregator, a crash reporter and a support ticket in
  one step. Redaction runs on the message, not on the developer's discipline;
* :func:`security_headers` — the headers are trivially checkable and trivially
  forgotten;
* :func:`check_cors` — ``Access-Control-Allow-Origin: *`` together with
  ``Allow-Credentials: true`` is not a hardening nit: it hands every site on the
  internet an authenticated session;
* :func:`parse_amount` — money arrives as text, and "just call float()" is how a
  payment platform loses a cent per transaction and then loses an audit.

None of this is a framework. It is the executable form of four baseline rows.
"""
from __future__ import annotations

import re

# Card-shaped digit runs, with the usual separators. Deliberately greedy about
# what counts as a candidate: a false positive costs a masked log line, a false
# negative costs a PAN in a support ticket.
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|authorization|private[_-]?key)"
    r"\s*[:=]\s*[\"']?([^\s\"',;)]+)")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_AMOUNT = re.compile(r"^-?\d+$")

REDACTED = "[REDACTED]"
MASKED_CARD = "[CARD]"

REQUIRED_HEADERS = {
    "strict-transport-security": "HSTS stops the first plaintext request",
    "content-security-policy": "CSP is the only defence that survives an XSS",
    "x-content-type-options": "stops MIME sniffing turning uploads into scripts",
    "referrer-policy": "keeps payment identifiers out of third-party referers",
}
FORBIDDEN_HEADERS = {"server", "x-powered-by"}


class ValidationError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def redact(text: str) -> str:
    """Remove card numbers and credential-shaped values from arbitrary text.

    Order matters, and it is not the obvious one. ``Bearer <token>`` is removed
    *before* the ``key=value`` pattern, because "Authorization: Bearer eyJ..."
    matches both, and the assignment pattern stops at the first space — it would
    replace the word "Bearer" and leave the token sitting in the log.
    Card numbers go last, since a redacted credential can no longer be mistaken
    for one.
    """
    if not text:
        return text
    out = _BEARER.sub(f"Bearer {REDACTED}", text)
    out = _SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}={REDACTED}", out)

    def mask(match: re.Match) -> str:
        candidate = match.group(0)
        return MASKED_CARD if luhn(candidate) else candidate

    return _CARD.sub(mask, out)


def security_headers(headers: dict[str, str]) -> list[str]:
    """Return the problems with a response's headers, empty when it is fine."""
    lowered = {k.lower(): v for k, v in headers.items()}
    problems = [f"missing {name}: {reason}"
                for name, reason in sorted(REQUIRED_HEADERS.items()) if name not in lowered]
    for name in sorted(FORBIDDEN_HEADERS):
        if name in lowered:
            problems.append(f"{name} advertises the stack for free")
    hsts = lowered.get("strict-transport-security", "")
    if hsts and "max-age=0" in hsts.replace(" ", ""):
        problems.append("strict-transport-security is disabled by max-age=0")
    nosniff = lowered.get("x-content-type-options", "")
    if nosniff and nosniff.lower() != "nosniff":
        problems.append("x-content-type-options must be exactly 'nosniff'")
    return problems


def check_cors(headers: dict[str, str]) -> list[str]:
    lowered = {k.lower(): str(v).lower() for k, v in headers.items()}
    origin = lowered.get("access-control-allow-origin", "")
    credentials = lowered.get("access-control-allow-credentials", "") == "true"
    problems: list[str] = []
    if origin == "*" and credentials:
        problems.append("wildcard origin with credentials exposes authenticated sessions "
                        "to every site on the internet")
    if origin == "null":
        problems.append("'null' origin is reachable from sandboxed frames and local files")
    return problems


def parse_amount(raw: object, *, currency_exponent: int, maximum_minor: int = 10 ** 12) -> int:
    """Parse a money amount in minor units, or refuse.

    Refuses floats outright — not because they are inconvenient, but because
    accepting one means the value has already lost precision before this
    function ever saw it.
    """
    if isinstance(raw, bool) or isinstance(raw, float):
        raise ValidationError("AMOUNT_NOT_INTEGER", f"{raw!r} is not an integer minor unit")
    if isinstance(raw, int):
        value = raw
    else:
        text = str(raw).strip()
        if not _AMOUNT.match(text):
            raise ValidationError("AMOUNT_NOT_INTEGER", f"{raw!r} is not a decimal integer")
        value = int(text)
    if value < 0:
        raise ValidationError("AMOUNT_NEGATIVE", "amounts are non-negative; refunds are their "
                                                 "own operation, not a negative payment")
    if value > maximum_minor:
        raise ValidationError("AMOUNT_TOO_LARGE", f"{value} exceeds {maximum_minor}")
    if currency_exponent < 0 or currency_exponent > 4:
        raise ValidationError("CURRENCY_EXPONENT", f"unsupported exponent {currency_exponent}")
    return value


def check_request(method: str, headers: dict[str, str]) -> list[str]:
    """The API-level rules that do not depend on a framework."""
    lowered = {k.lower(): v for k, v in headers.items()}
    problems: list[str] = []
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        if not lowered.get("idempotency-key"):
            problems.append("a mutating request without an idempotency key cannot be retried "
                            "safely, and every payment client retries")
    if not lowered.get("authorization"):
        problems.append("no authorization header; the gate is authentication, not the route")
    content_type = lowered.get("content-type", "")
    if method.upper() in {"POST", "PUT", "PATCH"} and content_type and \
            not content_type.startswith("application/json"):
        problems.append(f"unexpected content type {content_type!r}")
    return problems
