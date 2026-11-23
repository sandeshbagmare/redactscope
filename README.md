# redactscope

Remove the secrets that a tool result carries into the model's context, and report what
was there.

[![PyPI](https://img.shields.io/pypi/v/redactscope.svg)](https://pypi.org/project/redactscope/)
[![Python](https://img.shields.io/pypi/pyversions/redactscope.svg)](https://pypi.org/project/redactscope/)
[![tests](https://github.com/sandeshbagmare/redactscope/actions/workflows/ci.yml/badge.svg)](https://github.com/sandeshbagmare/redactscope/actions/workflows/ci.yml)
[![license](https://img.shields.io/pypi/l/redactscope.svg)](https://github.com/sandeshbagmare/redactscope/blob/main/LICENSE)

```python
>>> from redactscope import audit, redact
>>> message = {"role": "tool", "content": "token=sk-proj-8fJ2kLm4Qz7Vn1Xy3Wb6"}
>>> redact(message)["content"]
'token=***'
>>> [finding.kind for finding in audit(message)]
['openai-key']
```

Log redaction tools know about dict keys. Agent messages are worse than that: an env file
pasted into a tool result, a `curl` line with a bearer token, a stack trace with a
connection URL that has a password in it, a private key in a PEM block, a JWT in a cookie
header. None of those are under a key called `password`.

`redactscope` walks whatever the tool returned — dicts, lists, strings, JSON text — masks
secret-looking keys *and* secret-looking strings, and can tell you exactly what it found
without changing anything.

## Install

```console
pip install redactscope
```

## Use

```python
from redactscope import SecretLeak, assert_clean, audit, redact

clean = redact(tool_result)                 # a copy, never the original
findings = audit(tool_result)               # [Finding(path="metadata.api_key", kind="secret-key", …)]
assert_clean(tool_result)                   # raises SecretLeak, for a test or a gate
```

Wrapping a tool so nothing raw ever reaches the context:

```python
def safe_tool(function):
    def wrapper(*args, **kwargs):
        result = function(*args, **kwargs)
        findings = audit(result)
        if findings:
            log.warning("redacted %s", [str(finding) for finding in findings])
        return redact(result)
    return wrapper
```

```console
$ redactscope message.json > clean.json      # redacted JSON on stdout
$ redactscope trace.log                      # plain text works too
$ redactscope message.json --check           # exit 1 if anything was found
$ redactscope message.json --keys-only       # mask keys, leave other strings alone
```

## What is caught

| kind | example |
| ---- | ------- |
| `secret-key` | any key whose name contains `password`, `token`, `secret`, `api_key`, `authorization`, `credential`, `session`, `cookie`, `signature`, … |
| `openai-key` | `sk-…` (8+ characters after the prefix) |
| `anthropic-key` | `sk-ant-…` |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` |
| `slack-token` | `xoxb-`, `xoxp-`, `xoxa-`, … |
| `aws-access-key` | `AKIA…` / `ASIA…` + 16 characters |
| `google-api-key` | `AIza…` + 35 characters |
| `jwt` | three dot-separated base64url segments starting `eyJ` |
| `bearer` / `basic-auth` | `Bearer …`, `Basic …` |
| `url-credentials` | `postgres://user:password@host` |
| `private-key-block` | `-----BEGIN … PRIVATE KEY-----` … `-----END …` |

`audit` reports a path for each finding — `messages[0].content`, `metadata.api_key` — and
a preview that never contains the value itself.

## Rules

- `redact` returns a copy. Dict keys are kept, values are replaced with `***`.
- A string that is not a secret is returned unchanged; matching is on shapes that are
  unlikely in prose (`sk-` needs 8 more characters, `AKIA` needs 16).
- Pass `markers=(...)` to mask your own key names, `patterns=(...)` to narrow or extend
  the value patterns, `mask="[redacted]"` to change the replacement.
- Tuples become lists, because JSON has no tuples and a message usually ends up as JSON.
- `--keys-only` and `patterns=()` are the same decision: trust the key names and leave
  the strings alone.

## Limits

- This is a safety net, not a guarantee. A secret with no recognisable shape, in prose,
  under an innocent key will pass — nothing pattern-based can fix that.
- Patterns are chosen to avoid false positives, so a short custom token
  (`token=abc123`) is caught by its *key*, not by its value.
- No entropy analysis and no semantic detection: that is a different product with a
  different false-positive budget.
- Redaction is not a substitute for not collecting the secret in the first place.

## Development

```console
python -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/pytest
```

## License

MIT.
