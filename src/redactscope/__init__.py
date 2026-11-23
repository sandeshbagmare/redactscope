"""Find and redact secrets in agent messages before they reach a model or a log.

A tool result is a dict, a list, a JSON string, an error message, or all of them nested.
The secrets are not always under a key called ``password``: an API key in a URL, a bearer
token in a header, a private key block in a stack trace. Redacting only dict keys misses
most of them.

    >>> from redactscope import audit, redact
    >>> message = {"role": "tool", "content": "token=sk-proj-8fJ2kLm4Qz7Vn1Xy3Wb6"}
    >>> redact(message)["content"]
    'token=***'
    >>> [finding.kind for finding in audit(message)]
    ['openai-key']

Standard library only, Python 3.9+.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "DEFAULT_KEY_MARKERS",
    "DEFAULT_PATTERNS",
    "Finding",
    "SecretLeak",
    "audit",
    "assert_clean",
    "redact",
    "redact_text",
]

__version__ = "0.1.0"

MASK = "***"

DEFAULT_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "authorization",
    "auth",
    "credential",
    "private_key",
    "session",
    "cookie",
    "signature",
)

# name, compiled pattern. Ordered: earlier patterns win when two could match.
DEFAULT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key-block",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{8,}")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{8,}")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{8,}")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{8,}", re.IGNORECASE)),
    (
        "url-credentials",
        re.compile(r"\b((?:[a-z][a-z0-9+.\-]*://)[^/\s:@]+:)[^/\s@]+@", re.IGNORECASE),
    ),
    ("basic-auth", re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{16,}", re.IGNORECASE)),
)


@dataclass(frozen=True)
class Finding:
    """One secret, located by its path inside the value that was scanned."""

    path: str
    kind: str
    preview: str

    def __str__(self) -> str:
        return f"{self.path}: {self.kind}"


class SecretLeak(RuntimeError):
    """Raised by :func:`assert_clean` when a secret is still present."""

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        joined = ", ".join(str(finding) for finding in findings)
        super().__init__(f"{len(findings)} secret(s) found: {joined}")


def redact_text(
    text: str,
    *,
    patterns: tuple[tuple[str, re.Pattern[str]], ...] = DEFAULT_PATTERNS,
    mask: str = MASK,
) -> str:
    """Replace every pattern match in a string."""
    for kind, pattern in patterns:
        if kind == "url-credentials":
            text = pattern.sub(rf"\1{mask}@", text)
        elif kind == "bearer":
            text = pattern.sub(f"Bearer {mask}", text)
        elif kind == "basic-auth":
            text = pattern.sub(f"Basic {mask}", text)
        else:
            text = pattern.sub(mask, text)
    return text


def _path(parent: str, key: Any) -> str:
    return f"{parent}.{key}" if parent else str(key)


def redact(
    value: Any,
    *,
    markers: tuple[str, ...] = DEFAULT_KEY_MARKERS,
    patterns: tuple[tuple[str, re.Pattern[str]], ...] = DEFAULT_PATTERNS,
    mask: str = MASK,
) -> Any:
    """Return a copy with secret-looking keys and secret-looking strings masked.

    Dicts, lists and tuples are walked; strings are pattern-matched; numbers, booleans and
    ``None`` are returned unchanged. A tuple becomes a list, since JSON has no tuples.
    """
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if _is_secret_key(key, markers):
                redacted[key] = mask
            else:
                redacted[key] = redact(item, markers=markers, patterns=patterns, mask=mask)
        return redacted
    if isinstance(value, (list, tuple)):
        return [redact(item, markers=markers, patterns=patterns, mask=mask) for item in value]
    if isinstance(value, str):
        return redact_text(value, patterns=patterns, mask=mask)
    return value


def _is_secret_key(key: Any, markers: tuple[str, ...]) -> bool:
    name = str(key).lower().replace("-", "_").replace(" ", "_")
    return any(marker in name for marker in markers)


def audit(
    value: Any,
    *,
    markers: tuple[str, ...] = DEFAULT_KEY_MARKERS,
    patterns: tuple[tuple[str, re.Pattern[str]], ...] = DEFAULT_PATTERNS,
) -> list[Finding]:
    """List every secret found, without changing anything.

    A dict key is reported with its path and a preview of the masked value; a string is
    reported once per matching pattern.
    """
    findings: list[Finding] = []
    _walk(value, "", markers, patterns, findings)
    return findings


def _walk(
    value: Any,
    path: str,
    markers: tuple[str, ...],
    patterns: tuple[tuple[str, re.Pattern[str]], ...],
    findings: list[Finding],
) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            child = _path(path, key)
            if _is_secret_key(key, markers):
                findings.append(Finding(child, "secret-key", _preview(item)))
            else:
                _walk(item, child, markers, patterns, findings)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _walk(item, f"{path}[{index}]", markers, patterns, findings)
    elif isinstance(value, str):
        for kind, pattern in patterns:
            if pattern.search(value):
                findings.append(Finding(path or "…", kind, _preview(value)))


def _preview(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text[:12] + MASK if len(text) > 12 else MASK


def assert_clean(
    value: Any,
    *,
    markers: tuple[str, ...] = DEFAULT_KEY_MARKERS,
    patterns: tuple[tuple[str, re.Pattern[str]], ...] = DEFAULT_PATTERNS,
) -> None:
    """Raise :class:`SecretLeak` if anything secret is still in the value."""
    findings = audit(value, markers=markers, patterns=patterns)
    if findings:
        raise SecretLeak(findings)
