<p align="center">
  <img src="https://raw.githubusercontent.com/sandeshbagmare/redactscope/main/assets/banner.svg" width="100%" alt="redactscope: stop secrets in tool results before they reach the model">
</p>

<p align="center">
  <a href="https://pypi.org/project/redactscope/"><img alt="PyPI version" src="https://img.shields.io/pypi/v/redactscope.svg"></a>
  <a href="https://pypi.org/project/redactscope/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/redactscope.svg"></a>
  <a href="https://pypi.org/project/redactscope/"><img alt="Downloads" src="https://img.shields.io/pypi/dm/redactscope.svg"></a>
  <a href="https://github.com/sandeshbagmare/redactscope/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/sandeshbagmare/redactscope/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/sandeshbagmare/redactscope/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/pypi/l/redactscope.svg"></a>
  <a href="https://sandeshbagmare.github.io/redactscope/"><img alt="docs" src="https://img.shields.io/badge/docs-online-2ea44f.svg"></a>
  <a href="https://pypi.org/project/redactscope/"><img alt="zero dependencies" src="https://img.shields.io/badge/dependencies-0-2ea44f.svg"></a>
</p>

<h3 align="center">stop secrets in tool results before they reach the model</h3>
<p align="center"><em>Standard library only. No runtime dependencies. Python 3.9+.</em></p>

<p align="center">
  <img src="https://raw.githubusercontent.com/sandeshbagmare/redactscope/main/assets/how.svg" width="720" alt="how redactscope fits in">
</p>

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
